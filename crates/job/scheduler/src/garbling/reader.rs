//! Sequential topology file reader.
//!
//! Reads the 130GB topology file using `O_DIRECT` for unbuffered I/O. A single
//! reader thread reads sequentially, avoiding the disk thrashing that would
//! occur with multiple concurrent readers at different file offsets.
//!
//! The reader is started when the first garbling job registers and stopped when
//! the last job unregisters. Between read-throughs, it waits for new jobs to
//! arrive before starting the next pass.

use std::path::PathBuf;

/// A chunk of gate data read from the topology file.
///
/// Shared cheaply across all active garbling jobs via `Arc`. Each job
/// processes the same gates with its own seed, producing different garbled
/// output.
#[derive(Debug, Clone)]
pub struct GateChunk {
    /// Byte offset in the topology file where this chunk starts.
    pub offset: u64,
    /// Raw gate data.
    pub data: Vec<u8>,
    /// `true` if this is the last chunk in the topology file.
    pub is_last: bool,
}

/// Configuration for the topology reader.
#[derive(Debug, Clone)]
pub(crate) struct ReaderConfig {
    /// Path to the topology file.
    pub path: PathBuf,
    /// Size of each chunk read from disk.
    pub chunk_size: usize,
}

/// Control commands sent to the reader thread.
#[derive(Debug)]
pub(crate) enum ReaderCommand {
    /// Begin a new read-through of the topology file.
    Start,
    /// Stop the reader after the current chunk completes.
    Stop,
}

/// Handle to the reader thread.
///
/// The coordinator uses this to start/stop read-throughs and receive chunks.
pub(crate) struct TopologyReader {
    config: ReaderConfig,
    handle: Option<std::thread::JoinHandle<()>>,
    command_tx: Option<kanal::Sender<ReaderCommand>>,
    chunk_rx: Option<kanal::Receiver<GateChunk>>,
}

impl std::fmt::Debug for TopologyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologyReader")
            .field("config", &self.config)
            .field("running", &self.handle.is_some())
            .finish()
    }
}

impl TopologyReader {
    /// Create a new reader (does not start the thread yet).
    pub fn new(config: ReaderConfig) -> Self {
        Self {
            config,
            handle: None,
            command_tx: None,
            chunk_rx: None,
        }
    }

    /// Spawn the reader thread.
    ///
    /// The thread idles until it receives a [`ReaderCommand::Start`]. It then
    /// reads the topology file sequentially in chunks, sending each through the
    /// chunk channel. After the last chunk, it returns to the idle state and
    /// waits for the next command.
    pub fn spawn(&mut self) -> kanal::Receiver<GateChunk> {
        let (command_tx, command_rx) = kanal::bounded(1);
        let (chunk_tx, chunk_rx) = kanal::bounded(2); // small buffer for backpressure
        let config = self.config.clone();

        let handle = std::thread::Builder::new()
            .name("topology-reader".into())
            .spawn(move || {
                reader_loop(config, command_rx, chunk_tx);
            })
            .expect("failed to spawn topology reader thread");

        self.handle = Some(handle);
        self.command_tx = Some(command_tx);
        self.chunk_rx = Some(chunk_rx.clone());

        chunk_rx
    }

    /// Signal the reader to begin a new read-through.
    pub fn start_read(&self) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(ReaderCommand::Start);
        }
    }

    /// Signal the reader to stop after the current chunk.
    pub fn stop_read(&self) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(ReaderCommand::Stop);
        }
    }

    /// Shut down the reader thread.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.command_tx.take() {
            drop(tx); // closing the channel causes the reader loop to exit
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Main loop for the reader thread.
///
/// Waits for commands, then reads the topology file sequentially in chunks.
fn reader_loop(
    _config: ReaderConfig,
    command_rx: kanal::Receiver<ReaderCommand>,
    _chunk_tx: kanal::Sender<GateChunk>,
) {
    while let Ok(command) = command_rx.recv() {
        match command {
            ReaderCommand::Start => {
                // TODO: open topology file with O_DIRECT
                // TODO: read in chunk_size increments
                // TODO: send each GateChunk through chunk_tx
                // TODO: bounded channel provides backpressure — if workers are
                //       slow, the reader blocks on send until they catch up
                // TODO: after last chunk, return to idle
            }
            ReaderCommand::Stop => {
                // Reader returns to idle state. Any in-progress read is
                // abandoned at the next chunk boundary.
                continue;
            }
        }
    }
    // command_rx closed — thread exits
}
