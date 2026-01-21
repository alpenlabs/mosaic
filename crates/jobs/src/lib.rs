use kanal::{AsyncReceiver, AsyncSender};
use monoio::io::stream::Stream;
use std::{collections::VecDeque, fmt::Debug, sync::Arc};

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

struct IncomingNetworkMessage;
struct OutgoingNetworkMessage;

enum Action {}

#[repr(i32)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum MessagePriority {
    Low = -1,
    Normal = 0,
    High = 1,
}

impl Default for MessagePriority {
    fn default() -> Self {
        MessagePriority::Normal
    }
}

/// Queues
struct JobQueues {
    /// Network jobs are prioritized over other jobs. They're cheap to execute.
    net_jobs: VecDeque<Box<dyn Job>>,
    garbling_jobs: VecDeque<Box<dyn Job>>,
    other_jobs: VecDeque<Box<dyn Job>>,
}

trait NetworkSendingClient {
    async fn send_and_wait_for_ack(
        &self,
        to: PeerId,
        priority: Option<MessagePriority>,
        message: OutgoingNetworkMessage,
    ) -> Result<(), Error>;
}

trait NetworkReceivingClient {
    type Stream: Stream<Item = (IncomingNetworkMessage,)>;
    async fn receive(&self) -> Result<Option, Error>;
}

trait Acker {
    async fn ack(&self) -> Result<(), Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Utilisation {
    /// Memory usage in bytes
    memory: usize,
    /// Threads used for job execution
    threads: usize,
}

impl Utilisation {
    fn checked_sub(&self, other: &Utilisation) -> Option<Utilisation> {
        if self.memory < other.memory || self.threads < other.threads {
            None
        } else {
            Some(Utilisation {
                memory: self.memory - other.memory,
                threads: self.threads - other.threads,
            })
        }
    }

    fn checked_add(&self, other: &Utilisation, max: &Utilisation) -> Option<Utilisation> {
        if self.memory + other.memory > max.memory || self.threads + other.threads > max.threads {
            None
        } else {
            Some(Utilisation {
                memory: self.memory + other.memory,
                threads: self.threads + other.threads,
            })
        }
    }
}

pub struct JobScheduler {
    /// Immutable context shared with all jobs.
    ///
    /// We use an Arc as jobs are sent to individual threads
    context: Arc<JobContext>,
    max_util: Utilisation,
    cur_util: Utilisation,

    workers: Vec<SchedulerToWorker>,
}

struct SchedulerToWorker {
    to: AsyncSender<Job>,
}

impl JobScheduler {
    fn available_resources(&self) -> Utilisation {
        self.max_util
            .checked_sub(&self.cur_util)
            .expect("Utilisation underflow")
    }

    fn release_resources(&mut self, util: Utilisation) {
        self.cur_util = self
            .cur_util
            .checked_sub(&util)
            .expect("Utilisation overflow");
    }

    fn use_resources(&mut self, util: Utilisation) {
        self.cur_util = self
            .cur_util
            .checked_add(&util, &self.max_util)
            .expect("Utilisation overflow");
    }
}

struct JobContext {
    net_in: AsyncReceiver<IncomingNetworkMessage>,
    net_out: AsyncSender<OutgoingNetworkMessage>,

    actions_in: AsyncReceiver<Action>,
    action_results_out: AsyncSender<ActionResult>,
}

// SMExecutors send Actions to the JobScheduler
// JobScheduler transforms each Action into a Job and queues it for execution

trait Job {
    type Output;

    /// Returns an estimated memory requirement of the job in bytes.
    ///
    /// This helps the JobScheduler budget memory usage.
    fn memory_requirement(&self) -> Option<usize>;

    /// Executes the job with a global job context.
    async fn execute(&self, context: &JobContext) -> Result<Self::Output, Box<dyn Debug>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
