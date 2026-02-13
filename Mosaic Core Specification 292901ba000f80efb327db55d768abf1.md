# Mosaic Core Specification

Status: In progress
Author: Nakul Khambhati

**Mosaic** is a coordination crate that orchestrates all off-chain cryptographic execution in the bridge protocol. For a high-level overview of how Mosaic interfaces with the bridge, refer to [Cut and Choose](https://www.notion.so/Cut-and-Choose-278901ba000f80aab243c8766e3e38c9?pvs=21). This specification serves as an implementation guide, complementing the aforementioned document with details such as explicitly modeling the interacting parties - Garbler and Evaluator - as state machines, describing the various state transitions and messages exchanged between parties and implementation pseudocode. 

We logically separate each party’s states into 3 categories: Setup, Deposit and Withdrawal. 

# Overview

The following diagram provides an overview of the state transitions and messages exchanged during the Garbler and Evaluator interaction.

![Mosaic Core - Mosaic Core State Transitions + Side Effects-5.jpg](Mosaic%20Core%20Specification/Mosaic_Core_-_Mosaic_Core_State_Transitions__Side_Effects-5.jpg)

## Input handling

Mosaic is equipped to handle 3 different types of input based on when the data is available - setup input (`N_SETUP_INPUT_WIRES`), deposit input (`N_DEPOSIT_INPUT_WIRES`) and withdrawal input (`N_WITHDRAWAL_INPUT_WIRES`). 

Setup input data is public data known at setup time. The cryptographic data required to feed setup inputs into a garbled circuit is transferred and verified during Setup. We do not require generating adaptors or posting on-chain signatures for these inputs.

Deposit input data is public data known at deposit (graph generation) time. One adaptor is generated per input wire corresponding to the public value of that wire determined using the deposit input. These adaptors are verified and completed into signatures using the deposit input data, used to derive cryptographic data to feed deposit inputs into a garbled circuit. 

Withdrawal input data is provided by the garbler at withdrawal time. At deposit time, one adaptor is generated per value per input wire. All adaptors are verified. At withdrawal time, the garbler selects one adaptor per input wire, corresponding to the value of the input data byte and completes it to a signature. These are again used to derive cryptographic data to feed withdrawal inputs into a garbled circuit. 

# Setup

The Garbler and Evaluator are each initialized with an externally seeded CSPRNG used to generate, commit to and verify cryptographic data. These operations are independent of the bridge operation including the transaction graph and specific deposits/withdrawals and can be performed in advance. 

The Garbler is initialized with a CSPRNG which is used as the source of randomness to generate cryptographic data such as polynomials (`Polynomial`) and garbling tables (`GarblingTable`). As a part of the cut-and-choose protocol, the Garbler generates and commits to multiple garbling tables and input/output labels. Upon receiving these commitments, the Evaluator challenges the Garbler to open some commitments which the Evaluator verifies to protect against malicious behavior.

In this stage, Garbler initially sends Evaluator a `CommitMsg` , who stores this data and responds with a `ChallengeMsg` The Garbler responds with a `ResponseMsg` which is verified by Evaluator and also sends a `InputCommitMsg` which is verified and stored by the Evaluator to be used at Deposit time to generate adaptors (`Adaptor` ). 

## Setup Messages

```python
class SetupGarbData:
		config: Config
		rng: CSPRNG
		# setup input bytes
		setup_input: [u8; N_SETUP_INPUT_WIRES]
			
class SetupEvalData:
		config: Config
		rng: CSPRNG
		setup_input: [u8; N_SETUP_INPUT_WIRES]

class CommitMsg:
		# N_INPUT_WIRES * 256 + 1
		polynomial_commitments: List[List[[PolynomialCommitment](https://www.notion.so/VS3-Documentation-292901ba000f802189c2d3b9341dba94?pvs=21)]]
		# N_CIRCUITS
		garbling_table_commitments: List[GarblingTableCommitment]
	
class ChallengeMsg:
		# N_COEFFICIENTS
		challenge_indices: List[[Index](https://www.notion.so/VS3-Documentation-292901ba000f802189c2d3b9341dba94?pvs=21)]
	
class ResponseMsg:
		# N_COEFFICIENTS * N_INPUT_WIRES * 256
		opened_input_shares: List[List[List[Share]]]
		# N_SETUP_INPUT_WIRES * 256
		reserved_setup_input_shares: List[List[Share]]
		# N_COEFFICIENTS
		opened_output_shares: List[Share]
		# N_COEFFICIENTS
		opened_garbling_seeds: List[Seed]
		# N_CIRCUITS - N_COEFFICIENTS
		garbling_tables: List[GarblingTable]
```

## Garbler Setup

```python
class InitGarbState:
		rng: CSPRNG
		# setup input bytes
		setup_input: [u8; N_SETUP_INPUT_WIRES]
		
		def __init__(self, setup_data: SetupGarbData):
		    self.rng = setup_data.rng
		    self.setup_input = setup_data.setup_input
	

def exec_commit(state: InitGarbState) -> (WaitChalGarbState, CommitMsg):
	  rng = state.rng
	
	  # sample 256 input polynomials (1 for each possible value) for each of
	  # N_INPUT_WIRES many input wires
	  # and 1 output polynomial (false value)
		
		polynomials = [
		    [rand_poly(rng) for val in range(256)]
		    for wire in range(N_INPUT_WIRES)
		] + [[rand_poly(rng)]]
		
		# commit to each polynomial
		polynomial_commitments = [
		    [val_poly.commit() for val_poly in wire_polys]
		    for wire_polys in polynomials
		]
	
		# sample a garbling seed for each of N_CIRCUITS many circuits
		garbling_seeds = [rand_garbling_seeds(rng) for idx in range(N_CIRCUITS)]
		
		# generate input and output shares for each circuit by evaluating 
		# each polynomial at all indices i=1..N_CIRCUITS+1
		
		input_shares = [
		    [
		        [Share(idx, polynomials[wire][val].eval(idx)) for val in range(256)]
		        for wire in range(N_INPUT_WIRES)
		    ]
		    for idx in range(1, N_CIRCUITS + 1)
		]
		
		output_shares = [
				Share(idx, polynomials[-1][0].eval(idx)) for idx in range(1, N_CIRCUITS + 1)
		]
		
		# generate and commit to a garbled table for each circuit using garbling seeds,
		# input shares and output shares corresponding to each circuit index
		garbling_table_commitments = [
				gen_and_commit_table(garbling_seeds[idx], input_shares[idx], output_shares[idx])
				for idx in range(N_CIRCUITS)
		]
	
		next_state = WaitChalGarbState(
				rng,
				state.setup_input,
				polynomials,
				garbling_seeds,
		)
		
	  commit_msg = CommitMsg(
	      polynomial_commitments,
	      garbling_table_commitments,
	  )
	  
	  return next_state, commit_msg
	
	
class WaitChalGarbState: 
		rng: CSPRNG
		# setup input bytes
		setup_input: [u8; N_SETUP_INPUT_WIRES]
		# N_INPUT_WIRES * 256
		polynomials: List[List[[P](https://www.notion.so/VS3-Documentation-292901ba000f802189c2d3b9341dba94?pvs=21)olynomial]]
		# N_CIRCUITS
		garbling_seeds: [List[Seed]

	
def exec_respond(
    state: WaitChalGarbState, 
    msg: ChallengeMsg,
) -> (
    WaitAdaptorsGarbState,
    ResponseMsg,
):
		challenge_indices = msg.challenge_indices
		polynomials = state.polynomials
		garbling_seeds = state.garbling_seeds
		setup_input = state.setup_input
		
		# evaluate each input polynomial at the challenge_indices
		opened_input_shares = [
		    [
		        [Share(idx, polynomials[wire][val].eval(idx)) for val in range(256)]
		        for wire in range(N_INPUT_WIRES)
		    ]
		    for idx in challenge_indices
		]
		
		# evaluate the output false polynomial at the challenge indices
		opened_output_shares = [
		    Share(idx, polynomial_commitments[-1][0].eval(idx)) for idx in challenge_indices
		]
		
		# evaluate each input polynomial at the reserved i=0 index
		reserved_input_shares = [
				[Share(0, polynomials[wire][val].eval(0)) for val in range(256)]
				for wire in range(N_INPUT_WIRES)
		]
		
		# save reserved input shares for deposit and withdrawal inputs
		next_state = WaitAdaptorsGarbState(reserved_input_shares[N_SETUP_INPUT_WIRES:])
		
		# open reserved shares for public setup input
		reserved_setup_input_shares = [
				reserved_input_shares[wire][setup_input[wire]] for wire in range(N_SETUP_INPUT_WIRES)
		]
		
		# open garbling seeds for challenged circuits
    opened_garbling_seeds = [garbling_seeds[idx] for idx in challenge_indices]

    # generate garbling tables for UNCHALLENGED circuits
    challenge_set = set(challenge_indices)
    unchallenged_indices = [idx for idx in range(1, N_CIRCUITS+1) if idx not in challenge_set]
    garbling_tables = [gen_table(garbling_seeds[idx-1]) for idx in unchallenged_indices]

    response_msg = ResponseMsg(
        opened_input_shares,
        reserved_setup_input_shares,
        opened_output_shares,
        opened_garbling_seeds,
        garbling_tables,
    )

    return next_state, response_msg
		
	
class WaitAdaptorsGarbState:
		# (N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES) * 256 
		input_shares: List[List[[Scalar](https://www.notion.so/VS3-Documentation-292901ba000f802189c2d3b9341dba94?pvs=21)]]
```

## Evaluator Setup

```python
class InitEvalState:
		rng: CSPRNG
		setup_input: [u8; N_SETUP_INPUT_WIRES]
		
		def __init__(self, setup_data: SetupEvalData):
				self.rng = setup_data.rng
				self.setup_input = setup_data.setup_input

def exec_challenge(
    state: InitEvalState,
    msg: CommitMsg,
) -> (
    WaitRespEvalState,
    ChallengeMsg,
):
    rng = state.rng

    # sample a size-N_COEFFICIENTS subset of circuit indices without replacement
    challenge_indices = rng.sample(
        range(N_CIRCUITS),
        N_COEFFICIENTS,
    )

    # build the challenge message
    challenge_msg = ChallengeMsg(challenge_indices)

    # carry rng and commit data forward for response verification
    next_state = WaitRespEvalState(
        rng,
        state.setup_input,
        challenge_indices,
        msg.polynomial_commitments,
        msg.garbling_table_commitments,
    )

    return next_state, challenge_msg

class WaitRespEvalState:
		rng,
		setup_input: [u8; N_SETUP_INPUT_WIRES]
		# N_COEFFICIENTS
		challenge_indices: List[[Index](https://www.notion.so/VS3-Documentation-292901ba000f802189c2d3b9341dba94?pvs=21)]
		# N_INPUT_WIRES * 256
		polynomial_commitments: List[List[[P](https://www.notion.so/VS3-Documentation-292901ba000f802189c2d3b9341dba94?pvs=21)olynomialCommitment]]
		# N_COEFFICIENTS
		garbling_table_commitments: List[GTCommitment]
		

def exec_verify(
    state: WaitTxDataEvalState,
    response_msg: ResponseMsg,
) -> (
    WaitTxDataEvalState,
):
    polynomial_commitments = state.polynomial_commitments  
    garbling_table_commitments = state.garbling_table_commitments 
    challenge_indices = state.challenge_indices

    # ---------- 1) Verify opened input shares against polynomial commitments ----------
    opened_input_shares = response_msg.opened_input_shares

    for idx in challenge_indices:
        for wire in range(N_INPUT_WIRES):
            for val in range(256):
		            share = opened_input_shares[idx][wire][val]
                if not polynomial_commitments[wire][val].verify_share(share):
                    raise Error(
                        f"verify opened input shares failed for index {idx}, wire {wire}, value {val}"
                    )

		
    # ---------- 2) Verify opened output (false) shares ----------
    opened_output_shares = response_msg.opened_output_shares  
    output_poly_commit = polynomial_commitments[-1][0]
    for idx in challenge_indices:
		    share = opened_output_shares[idx]
        if not output_poly_commit.verify_share(share):
            raise Error(f"verify_share failed for output, index {idx}")

    # ---------- 3) Verify garbling table commitments ----------
    # 3a) Challenged circuits: verify via opened seeds -> gen_and_commit_table(seed)
    opened_seeds = response_msg.opened_garbling_seeds 
    for seed, idx in zip(opened_seeds, challenge_indices):
        expected_commit = gen_and_commit_table(seed)
        if expected_commit != garbling_table_commitments[idx-1]:
            raise Error(f"garbling seed commit mismatch at index {idx}")

    # 3b) Unchallenged circuits: verify provided tables against commitments
    challenge_set = set(challenge_indices)
    unchallenged = [idx for idx in range(1, N_CIRCUITS+1) if idx not in challenge_set]
    tables = response_msg.garbling_tables 
    for table, idx in zip(tables, unchallenged):
        if table.commit() != garbling_table_commitments[idx-1]:
            raise Error(f"garbling table commit mismatch at index {idx}")

		# 4) Verify setup input shares against setup input and polynomial commitments
    reserved_setup_input_shares = response_msg.reserved_setup_input_shares
    for wire in range(N_INPUT_WIRES):
		    let val = setup_input[wire]
        share = reserved_setup_input_shares[wire][val]
            if not polynomial_commitments[wire][val].verify_share(share):
                raise Error(
                    f"verify reserved setup shares failed for wire {wire}"
                )
                
    # store input share commitments at reserved index 
    input_share_commitments = [
		    [polynomial_commitments[wire][val].eval(0) for val in range(256)]
		    for wire in range(N_SETUP_INPUT_WIRES, N_INPUT_WIRES)
	  ]
     
	  next_state = WaitTxDataEvalState(
		    state.rng
		    challenge_indices
		    opened_input_shares
		    reserved_setup_input_shares
		    opened_output_shares
		    garbling_tables
		    input_share_commitments
		    # zero coefficient of output polynomial
		    polynomial_commitments[-1][0]
		 )

class WaitTxDataEvalState:
		rng: CSPRNG
		# N_COEFFICIENTS
		challenge_indices: List[Index]
		# N_COEFFICIENTS * N_INPUT_WIRES * 256
    opened_input_shares: List[List[List[Scalar]]]
    # N_SETUP_INPUT_WIRES
    reserved_setup_input_shares: List[Scalar]
    # N_COEFFICIENTS
    opened_output_shares: [List[Scalar]
    # N_CIRCUITS - N_COEFFICIENTS
    garbling_tables: List[GarblingTables]
    # (N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES) * 256
    input_share_commitments: List[List[Point]]
    output_commitment: Point
```

The Evaluator may detect malicious behavior at `exec_verify` which would result in the protocol being aborted immediately. 

## Setup Interaction

```python
garbler = InitGarbState(init_garb_data)
evaluator = InitEvalState(init_eval_data)

# Garbler: InitGarbState -> WaitChalGarbState
garbler, commitment = exec_commit(garbler)

# Evaluator: InitEvalState -> WaitRespEvalState
# (stores commitment, issues challenge)
evaluator, challenge = exec_challenge(
    evaluator,
    commitment,
)

# Garbler: WaitChalGarbState -> WaitAdaptorsGarbState
# (sends openings for challenged indices + setup inputs)
garbler, response = exec_respond(
    garbler,
    challenge,
)

# Evaluator: WaitRespEvalState -> WaitTxDataEvalState on success,
# or ABORT on failure
evaluator = exec_verify(
    evaluator,
    response,
    input_commitment,
)
```

# Deposit

When the transaction graph has been generated, the Evaluator can create Adaptors using data passed in from the bridge and send them to the Garbler who will verify and store them for use during withdrawal. 

## Deposit Messages

```python
class DepositGarbData:
		# N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES
		sighashes: List[Sighash]
		# public key used to verify adaptors created under evaluator's secret key
		pk: Point
    deposit_input: [u8; N_DEPOSIT_INPUT_WIRES]
    
class DepositEvalData:
		# N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES
		sighashes: List[Sighash]
    # secret key used to generate adaptors which are sent to garbler
    sk: Scalar
    deposit_input: [u8; N_DEPOSIT_INPUT_WIRES]

class AdaptorsMsg:
	# N_DEPOSIT_INPUT_WIRES
	deposit_adaptors: List[Adaptors]
	# N_WITHDRAWAL_INPUT_WIRES * 256
	withdrawal_adaptors: List[List[[Adaptor](https://www.notion.so/Adaptor-Documentation-292901ba000f80608a09cf6a594a31c9?pvs=21)]]
```

## Garbler Deposit

```python
class WaitAdaptorsGarbState:
		# (N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES) * 256 
    input_shares: List[List[Scalar]]

def exec_verify_adaptors(
    state: WaitAdaptorsGarbState,
    # passed in externally from the bridge
    deposit_data: DepositGarbData,
    adaptor_msg: AdaptorsMsg,
) -> WaitProofGarbState:
    
    sighashes = deposit_data.sighashes
    pk = deposit_data.pk
    deposit_input = deposit_data.deposit_input
    deposit_adaptors = adaptor_msg.deposit_adaptors
    withdrawal_adaptors = adaptor_msg.withdrawal_adaptors
    input_shares = state.input_shares
    
    # select deposit input shares using deposit_input, one per wire
    deposit_input_shares = [
		    input_shares[wire][deposit_input[wire]]
		    for wire in range(N_DEPOSIT_INPUT_WIRES)
    ]
    
    # withdrawal input not yet known, store one per value, per wire
    withdrawal_input_shares = input_shares[N_DEPOSIT_INPUT_WIRES:]
   
    # Verify deposit adaptors with sighash, input shares
    for wire, adapator in enumerate(deposit_adaptors):
		    if not adaptor.verify(pk, sighashes[wire], deposit_input_shares[wire]:
				    raise Error
				    
    # Verify withdrawal adaptors with wire-specific sighash, input shares
		for wire, wire_adaptors in enumerate(withdrawal_adaptors):
		    for val, adaptor in enumerate(wire_adaptors):
		        if not adaptor.verify(
				        pk, 
				        sighashes[N_DEPOSIT_INPUT_WIRES + wire], 
				        withdrawal_input_shares[wire][val]
				     ):
		            raise Error
    
    next_state = WaitProofGarbState(
	      deposit_input_shares,
	      withdrawal_input_shares,
		    deposit_adaptors,
		    withdrawal_adaptors,
    )
    
    return next_state, adaptor_msg

class WaitProofGarbState:
		# N_DEPOSIT_INPUT_WIRES
		deposit_input_shares,
	  # N_WITHDRAWAL_INPUT_WIRES * 256
	  withdrawal_input_shares,
    # N_DEPOSIT_INPUT_WIRES
    deposit_adaptors: List[Adaptor]
    # N_WITHDRAWAL_INPUT_WIRES * 256
    withdrawal_adaptors: List[List[Adaptor]]
```

## Evaluator Deposit

```python
class WaitTxDataEvalState:
		rng: CSPRNG
		# N_COEFFICIENTS
		challenge_indices: List[Index]
		# N_COEFFICIENTS * N_INPUT_WIRES * 256
    opened_input_shares: List[List[List[Scalar]]]
    # N_SETUP_INPUT_WIRES
    reserved_setup_input_shares: List[Scalar]
    # N_COEFFICIENTS
    opened_output_shares: [List[Scalar]
    # N_CIRCUITS - N_COEFFICIENTS
    garbling_tables: List[GarblingTables]
    # (N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES) * 256
    input_share_commitments: List[List[Point]]
    output_commitment: Point

def exec_generate_adaptors(
    state: WaitTxDataEvalState,
    deposit_data: DepositEvalData
) -> (
    WaitSigEvalState,
    AdaptorMsg,
):
    rng = state.rng
    input_share_commitments = state.input_share_commitments
    sighashes = deposit_data.sighashes
    sk = deposit_data.sk
    deposit_input = deposit_data.deposit_input
    
		# generate adaptors corresponding to deposit input
    deposit_adaptors = [
		    gen_adaptor(rng, sk, input_share_commitments[wire][deposit_input[wire]], sighashes[wire])
		    for wire in range(N_DEPOSIT_INPUT_WIRES)
    ]
    
    # 2D array of adaptors for withdrawal inputs: per value per wire, 
    # using the same sighash across values of a wire
    withdrawal_adaptors = [
        [
            gen_adaptor(rng, sk, share_commit, sighashes[wire])
            for share_commit in wire_share_commits
        ]
        for wire, wire_share_commits in enumerate(input_share_commitments[N_DEPOSIT_INPUT_WIRES:])
    ]
    
    adaptor_msg = AdaptorMsg(deposit_adaptors, withdrawal_adaptors)
    
    next_state = WaitSigEvalState(
	      state.opened_input_shares,
		    state.opened_output_shares,
		    state.garbling_tables,
		    deposit_adaptors,
		    withdrawal_adaptors
    )
    
    return next_state, adaptor_msg

class WaitSigEvalState:
		# N_COEFFICIENTS
		challenge_indices: List[Index]
    # N_COEFFICIENTS * N_INPUT_WIRES * 256
    opened_input_shares: List[List[List[Scalar]]]
    # N_COEFFICIENTS
    opened_output_shares: List[Scalar]
    # N_CIRCUITS - N_COEFFICIENTS
    garbling_tables: List[GarblingTables]
    # N_DEPOSIT_INPUT_WIRES
    deposit_adaptors: List[Adaptor]
    # N_WITHDRAWAL_INPUT_WIRES * 256
    withdrawal_adaptors: List[List[Adaptor]]
    output_poly_commitment: List[Point]
```

## Deposit Interaction

```python
# Evaluator: WaitTxDataEvalState -> WaitSigEvalState
# (derives adaptor signatures from deposit data; sends to Garbler)
evaluator, adaptors = exec_generate_adaptors(
    evaluator,
    deposit_eval_data,
)

# Garbler: WaitAdaptorsGarbState -> WaitProofGarbState (verifies adaptors)
garbler = exec_verify_adaptors(
    garbler,
    deposit_garb_data,
    adaptors,
)
```

# Withdrawal

The Garbler is passed in a proof (in bytes) from the bridge, which is used as input to the garbled circuit. To reveal this input in an authenticated manner, the Garbler selectively completes some adaptors and posts signatures on-chain. This binds the Garbler to a specific input and allows the Evaluator to extract from these signatures input shares corresponding to the bytes of `ProofMsg`. These input shares, along with the previously opened input shares are used by the Evaluator to interpolate appropriate polynomials and obtain input labels for all garbled tables. The Evaluator evaluates garbled tables until it outputs a false label, which is used to interpolate the output polynomial that reveals a fault secret.

## Withdrawal Messages

```python
class WithdrawalGarbData:
		withdrawal_input: [u8; N_WITHDRAWAL_INPUT_WIRES]
		
class WithdrawalEvalData:
		withdrawal_input: [u8; N_WITHDRAWAL_INPUT_WIRES]
	
class SigMsg:
		withdrawal_input: [u8; N_WITHDRAWAL_INPUT_WIRES]
		# N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES
		signatures: List[[Signature](https://www.notion.so/Adaptor-Documentation-292901ba000f80608a09cf6a594a31c9?pvs=21)]
```

## Garbler Withdrawal

```python
class WaitProofGarbState:
		# N_DEPOSIT_INPUT_WIRES
		deposit_input_shares,
	  # N_WITHDRAWAL_INPUT_WIRES * 256
	  withdrawal_input_shares,
    # N_DEPOSIT_INPUT_WIRES
    deposit_adaptors: List[Adaptor]
    # N_WITHDRAWAL_INPUT_WIRES * 256
    withdrawal_adaptors: List[List[Adaptor]]

def exec_sign(
	    state: WaitProofGarbState,
	    withdrawal_data: WithdrawalGarbData,
) -> (
	    FinishGarbState,
	    SigMsg,
):
		deposit_input_shares = state.deposit_input_shares
		withdrawal_input_shares = state.withdrawal_input_shares
		
		deposit_adaptors = state.deposit_adaptors
		withdrawal_adaptors = state.withdrawal_adaptors
		
		withdrawal_input = withdrawal_data.withdrawal_input
		
		# complete one signature per wire corresponding to the proof
		signatures = []
		
		# the adaptors here already correspond to the deposit input
		for wire, adaptor in enumerate(deposit_adaptors):
				sig = adaptor.complete(deposit_input_shares[wire])
		    signatures.append(sig)
		
		# selectively complete adaptors corresponding to the withdrawal input
		for wire, wire_adaptors in enumerate(withdrawal_adaptors):
		    val = withdrawal_input[wire]
		    sig = adaptor.complete(withdrawal_input_shares[wire][val])
		    signatures.append(sig)
		    
		 next_state = FinishGarbState
		 
		 sig_msg = SigMsg(withdrawal_input, signatures)
		 
		 return next_state, sig_msg
    

class FinishGarbState
```

## Evaluator Withdrawal

```python
class WaitSigEvalState:
		# N_COEFFICIENTS
		challenge_indices: List[Index]
    # N_COEFFICIENTS * N_INPUT_WIRES * 256
    opened_input_shares: List[List[List[Scalar]]]
    # N_COEFFICIENTS
    opened_output_shares: List[Scalar]
    # N_CIRCUITS - N_COEFFICIENTS
    garbling_tables: List[GarblingTables]
    # N_DEPOSIT_INPUT_WIRES
    deposit_adaptors: List[Adaptor]
    # N_WITHDRAWAL_INPUT_WIRES * 256
    withdrawal_adaptors: List[List[Adaptor]]
    output_poly_commitment: List[Point]

def exec_try_reveal_secret(
    state: WaitSigEvalState,
    msg: SigMsg,
) -> FinishEvalState:
    deposit_adaptors = state.deposit_adaptors
    withdrawal_adaptors = state.withdrawal_adaptors
    opened_input_shares = state.opened_input_shares        
    challenge_indices = state.challenge_indices            

    withdrawal_input = msg.withdrawal_input                          
    signatures = msg.signatures                            

    selected_input_shares = []

    # extract shares from signatures corresponding to deposit input
		for wire, adaptor in enumerate(deposit_adaptors):
				share = adaptor.extract_share(signatures[wire])
		    selected_input_shares.append(share)
		
		# extract shares from signatures using adaptors corresponding to withdrawal input
		for wire, wire_adaptors in enumerate(withdrawal_adaptors):
		    val = withdrawal_input[wire]
		    share = wire_adaptors[val].extract_share(signatures[wire])
		    selected_input_shares.append(share)
		
		selected_input_shares = [selected_input_shares].append(opened_input_shares)
		
    # Interpolate per wire
    selected_input_polynomials = [interpolate(input_shares) for input_shares in selected_input_shares]
    
		challenge_set = set(challenge_indices)
		unchallenged_indices = [i for i in range(N_CIRCUITS) if i not in challenge_set]
		
		# garbling_input_shares[evaluation_index][wire_index] = share value
		garbling_input_shares = []
		
		for eval_idx in unchallenged_indices:
		    shares_for_eval = []
		    for wire_idx, poly in enumerate(selected_input_polynomials):
		        share_val = poly.eval(eval_idx)
		        shares_for_eval.append(share_val)
		    garbling_input_shares.append(shares_for_eval)
		    
		 secret = None
		 secret_commit = state.output_commitment
		 for i in len(garbling_tables):
				 evaluated_output_share = evaluate(garbling_tables[i], garbling_input_shares[i])
				 output_shares = opened_output_shares.append(evaluated_output_share)
				 candidate_secret = interpolate(output_shares).eval(0)
				 if candidate_secret.commit == secret_commit:
						 secret = candidate_secret
						 break
		 
		 return FinishGarbState(secret)

class FinishEvalState:
    fault_secret: Optional[Scalar]

```

## Withdrawal Interaction

```python
# Garbler: WaitProofGarbState -> FinishGarbState
# (uses bridge proof to complete adaptors and post Schnorr signatures on-chain)
garbler, signatures = exec_sign(
    garbler,
    withdrawal_garb_data,
)

# Evaluator: WaitSigEvalState -> FinishEvalState
# (extracts input shares from on-chain signatures to reconstruct fault secret)
evaluator = exec_try_reveal_secret(
    evaluator,
    signatures,
)
```