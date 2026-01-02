use std::{collections::HashMap, sync::mpsc};

use mosaic_state_machine_api::{
    ExecutorControlMsgType, ExecutorInput, ExecutorInputMsg, ExecutorInputMsgType, ExecutorOutput,
    ExecutorOutputMsgType, StateMachineAdaptorSpec, StateMachineData, StateMachineInitData,
    StateMachineMetadata, StateMachinePairId,
};
use mosaic_storage_api::StateMachineDb;
use tracing::{error, warn};

/// Cache of recently used state machines by the executor.
struct ExecutorCache<Spec: StateMachineAdaptorSpec, Db: StateMachineDb> {
    /// cache of recently used state machine states
    state_cache: HashMap<StateMachinePairId, StateMachineData<Spec>>,
    storage: Db,
}

impl<Spec: StateMachineAdaptorSpec, Db: StateMachineDb> ExecutorCache<Spec, Db> {
    fn new_empty(storage: Db) -> Self {
        Self {
            state_cache: HashMap::new(),
            storage,
        }
    }
}

impl<Spec: StateMachineAdaptorSpec, Db: StateMachineDb> ExecutorCache<Spec, Db> {
    fn get_or_load_state_machine(
        &mut self,
        id: StateMachinePairId,
    ) -> Option<&StateMachineData<Spec>> {
        if !self.state_cache.contains_key(&id) {
            match self.storage.load_state::<Spec>(&id) {
                Ok(Some(state_machine_data)) => {
                    self.state_cache.insert(id, state_machine_data);
                }
                Ok(None) => return None,
                Err(err) => {
                    warn!(%err, "error fetching state machine from storage");
                    // TODO: retry
                    return None;
                }
            }
        }
        self.state_cache.get(&id)
    }

    fn save_state_machine(
        &mut self,
        id: StateMachinePairId,
        data: StateMachineData<Spec>,
        active: bool,
    ) -> bool {
        // TODO: cache invaliation; or use LRU
        if let Err(err) = self.storage.save_state(&id, &data, active) {
            error!(%err, "failed to save state");
            return false;
        }
        self.state_cache.insert(id, data);

        true
    }
}

/// Run an executor that handles multiple state machines of one type.
pub fn run_executor<Spec: StateMachineAdaptorSpec>(
    input_rx: mpsc::Receiver<ExecutorInput>,
    output_tx: mpsc::Sender<ExecutorOutput>,
    storage: impl StateMachineDb,
) {
    let mut exec_cache = ExecutorCache::<Spec, _>::new_empty(storage);

    'top: while let Ok(msg) = input_rx.recv() {
        let id = msg.state_machine_id;
        let output_msgs = match msg.msg {
            ExecutorInputMsg::Control(ExecutorControlMsgType::Init(init_data, metadata)) => {
                handle_init_state_machine(id, init_data, metadata, &mut exec_cache)
            }
            ExecutorInputMsg::Control(ExecutorControlMsgType::Load) => {
                handle_load_state_machine(id, &mut exec_cache)
            }
            ExecutorInputMsg::Input(executor_input_msg_type) => {
                handle_input_msg(id, executor_input_msg_type, &mut exec_cache)
            }
        };

        // 6. Send output messages
        for msg in output_msgs {
            if output_tx
                .send(ExecutorOutput {
                    state_machine_id: id,
                    msg,
                })
                .is_err()
            {
                // channel is closed
                warn!("output_tx channel closed");
                break 'top;
            }
        }
    }

    // warn channel closed
    warn!("channel(s) closed; exiting");
}

fn handle_input_msg<Spec: StateMachineAdaptorSpec, Db: StateMachineDb>(
    id: StateMachinePairId,
    msg: ExecutorInputMsgType,
    exec_cache: &mut ExecutorCache<Spec, Db>,
) -> Vec<ExecutorOutputMsgType> {
    // 1. Load state machine instance corresponding to input message id.
    // check if id is in cached state, otherwise load
    let Some(state_machine) = exec_cache.get_or_load_state_machine(id) else {
        // state machine not found
        error!(%id, "state machine not found");
        return vec![];
    };

    let config = &state_machine.config;
    let mut output_msgs = vec![];

    // 2. Process input messages to get state machine inputs and early output messages.
    let (inputs, mut msgs) = Spec::process_input(&state_machine.work_state, msg);
    output_msgs.append(&mut msgs);

    // 3. Run stf for each input and get output actions.
    let mut state = state_machine.state.clone();
    let mut actions = vec![];
    for input in inputs {
        state = Spec::stf(config, state, input);
        actions.append(&mut Spec::emit_actions(config, &state));
    }

    // 4. Process emitted actions to get output messages.
    let mut ws = state_machine.work_state.clone();
    for action in actions {
        // 1 action will almost map to 1 msg, but keeping it flexible
        let (next_ws, mut msgs) = Spec::process_action(ws, action);
        output_msgs.append(&mut msgs);
        ws = next_ws;
    }

    // 5. Save if state is changed.
    if ws != state_machine.work_state || state != state_machine.state {
        let next = StateMachineData::<Spec> {
            state,
            work_state: ws,
            metadata: state_machine.metadata.clone(),
            config: state_machine.config.clone(),
        };
        // if there are any output messages, then this state should be marked `active`.
        let active = !output_msgs.is_empty();
        if !exec_cache.save_state_machine(id, next, active) {
            return vec![];
        }
    }
    output_msgs
}

fn handle_load_state_machine<Spec: StateMachineAdaptorSpec, Db: StateMachineDb>(
    id: StateMachinePairId,
    exec_cache: &mut ExecutorCache<Spec, Db>,
) -> Vec<ExecutorOutputMsgType> {
    // 1. Load state machine instance corresponding to input message id.
    // check if id is in cached state, otherwise load
    let Some(state_machine) = exec_cache.get_or_load_state_machine(id) else {
        // state machine not found
        error!(%id, "state machine not found");
        return vec![];
    };

    // 2. Generate actions from current state
    let config = &state_machine.config;
    let state = &state_machine.state;
    let actions = Spec::emit_actions(config, state);

    // 3. Process emitted actions to get output messages.
    let mut output_msgs = vec![];
    let mut ws = state_machine.work_state.clone();
    for action in actions {
        // 1 action will almost map to 1 msg, but keeping it flexible
        let (next_ws, mut msgs) = Spec::process_action(ws, action);
        output_msgs.append(&mut msgs);
        ws = next_ws;
    }

    // 4. Save if state is changed.
    if ws != state_machine.work_state {
        let next = StateMachineData::<Spec> {
            state: state.clone(),
            work_state: ws,
            metadata: state_machine.metadata.clone(),
            config: state_machine.config.clone(),
        };
        // if there are any output messages, then this state should be marked `active`.
        let active = !output_msgs.is_empty();
        if !exec_cache.save_state_machine(id, next, active) {
            return vec![];
        }
    }
    output_msgs
}

fn handle_init_state_machine<Spec: StateMachineAdaptorSpec, Db: StateMachineDb>(
    id: StateMachinePairId,
    init_data: StateMachineInitData,
    metadata: StateMachineMetadata,
    exec_cache: &mut ExecutorCache<Spec, Db>,
) -> Vec<ExecutorOutputMsgType> {
    // 1. Check if requested state machine instance already exists.
    if exec_cache.get_or_load_state_machine(id).is_some() {
        // state machine with this id already exists
        error!(%id, "state machine already exists; cannot init");
        return vec![];
    };

    // 2. Init state machine
    let Some((config, state, mut ws)) = Spec::process_init(init_data) else {
        error!(%id, "failed to init state machine");
        return vec![];
    };

    // 3. Generate actions from current state
    let actions = Spec::emit_actions(&config, &state);

    // 4. Process emitted actions to get output messages.
    let mut output_msgs = vec![];
    for action in actions {
        // 1 action will almost map to 1 msg, but keeping it flexible
        let (next_ws, mut msgs) = Spec::process_action(ws, action);
        output_msgs.append(&mut msgs);
        ws = next_ws;
    }

    // 3. Save state machine
    {
        let state_machine_data = StateMachineData::<Spec> {
            state,
            work_state: ws,
            metadata,
            config,
        };
        // if there are any output messages, then this state should be marked `active`.
        let active = !output_msgs.is_empty();
        if !exec_cache.save_state_machine(id, state_machine_data, active) {
            return vec![];
        }
    }
    output_msgs
}
