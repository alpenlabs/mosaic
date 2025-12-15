//! Opaque notification handles for input arrival and shutdown signaling.
//!
//! These handles abstract over the underlying notification mechanism, allowing
//! the implementation to change (e.g., from watch channels to broadcast) without
//! breaking user code.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::watch;

use crate::error::{Error, Result};

/// Receiver handle for input notifications.
///
/// The worker holds this and waits for notifications that new inputs are
/// available in the durable queue.
#[derive(Debug)]
pub struct InputNotifier {
    rx: watch::Receiver<u64>,
}

impl InputNotifier {
    /// Creates a new notifier from a watch receiver.
    pub(crate) fn new(rx: watch::Receiver<u64>) -> Self {
        Self { rx }
    }

    /// Waits for a notification that new inputs are available.
    ///
    /// Returns when signaled or when the sender is dropped.
    pub async fn wait(&mut self) -> Result<()> {
        self.rx.changed().await.map_err(|_| Error::ChannelClosed)
    }

    /// Checks if there's a pending notification without blocking.
    pub fn has_pending(&self) -> bool {
        self.rx.has_changed().unwrap_or(false)
    }
}

/// Sender handle for input notifications.
///
/// External code holds this and calls [`notify`](Self::notify) after persisting
/// new inputs to the durable queue.
#[derive(Debug, Clone)]
pub struct InputSender {
    tx: watch::Sender<u64>,
    counter: Arc<AtomicU64>,
}

impl InputSender {
    /// Creates a new sender.
    pub(crate) fn new(tx: watch::Sender<u64>) -> Self {
        Self {
            tx,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Notifies the worker that new inputs are available.
    ///
    /// This is cheap to call multiple times - the worker will process all
    /// available inputs when it wakes.
    pub fn notify(&self) {
        let val = self.counter.fetch_add(1, Ordering::Relaxed);
        // Ignore send errors - worker may have shut down
        let _ = self.tx.send(val + 1);
    }
}

/// Creates a paired notifier and sender for input coordination.
pub fn create_input_channel() -> (InputNotifier, InputSender) {
    let (tx, rx) = watch::channel(0u64);
    (InputNotifier::new(rx), InputSender::new(tx))
}

/// Handle for requesting worker shutdown.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signals the worker to shut down gracefully.
    pub fn shutdown(&self) {
        let _ = self.tx.send(true);
    }
}

/// Receiver for shutdown signals.
#[derive(Debug)]
pub struct ShutdownReceiver {
    rx: watch::Receiver<bool>,
}

impl ShutdownReceiver {
    /// Checks if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        *self.rx.borrow()
    }

    /// Waits for shutdown signal.
    pub async fn wait_for_shutdown(&mut self) {
        while !*self.rx.borrow() {
            if self.rx.changed().await.is_err() {
                break;
            }
        }
    }
}

/// Creates a shutdown signal pair.
pub fn create_shutdown_channel() -> (ShutdownHandle, ShutdownReceiver) {
    let (tx, rx) = watch::channel(false);
    (ShutdownHandle { tx }, ShutdownReceiver { rx })
}
