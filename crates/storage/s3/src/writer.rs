//! S3-backed [`TableWriter`] implementation.
//!
//! Streams ciphertext data to the background tokio runtime which performs
//! multipart uploads via `object_store`. Translation material and metadata
//! are uploaded into immutable versioned object paths, and the table becomes
//! visible only once the live commit marker is published during
//! [`finish`](S3TableWriter::finish).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use mosaic_storage_api::table_store::{TableMetadata, TableWriter};
use object_store::{ObjectStore, ObjectStoreExt};
use tracing::error;

use crate::{
    error::S3Error,
    paths::{TableRootPaths, TableVersionPaths},
};

/// Commands sent from the monoio caller to the background tokio writer task.
enum WriterCmd {
    /// Append ciphertext bytes.
    Write(Vec<u8>),
    /// Finalize: flush remaining ciphertext, upload translation + metadata.
    Finish {
        translation: Vec<u8>,
        metadata_bytes: Vec<u8>,
    },
}

/// Streams garbling table data to object storage via a background tokio task.
///
/// Ciphertext chunks are buffered and uploaded as multipart parts when the
/// buffer exceeds the store's configured part buffer size (default
/// [`DEFAULT_PART_BUFFER_SIZE`](crate::DEFAULT_PART_BUFFER_SIZE)).
/// Translation material and metadata are
/// written under an immutable version prefix, then a live commit marker is
/// published on [`finish`](Self::finish).
///
/// Dropping without calling `finish` aborts the multipart upload.
#[derive(Debug)]
pub struct S3TableWriter {
    /// Channel for sending commands to the background task.
    cmd_tx: kanal::AsyncSender<WriterCmd>,
    /// Channel for receiving the final result from the background task.
    result_rx: kanal::AsyncReceiver<Result<(), S3Error>>,
}

impl S3TableWriter {
    /// Create a new writer. Spawns a background task on the provided tokio
    /// runtime that manages the multipart upload.
    pub(crate) async fn new(
        store: Arc<dyn ObjectStore>,
        rt_handle: tokio::runtime::Handle,
        root_paths: TableRootPaths,
        part_buffer_size: usize,
    ) -> Result<Self, S3Error> {
        let version_paths = root_paths.allocate_version_paths();
        let (cmd_tx, cmd_rx) = kanal::bounded_async(crate::STREAM_CHANNEL_CAPACITY);
        let (result_tx, result_rx) = kanal::bounded_async(1);

        rt_handle.spawn(background_writer(
            store,
            root_paths,
            version_paths,
            part_buffer_size,
            cmd_rx,
            result_tx,
        ));

        Ok(Self { cmd_tx, result_rx })
    }
}

impl TableWriter for S3TableWriter {
    type Error = S3Error;

    fn write_ciphertext(
        &mut self,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let chunk = data.to_vec();
        let tx = self.cmd_tx.clone();
        async move {
            tx.send(WriterCmd::Write(chunk))
                .await
                .map_err(|_| S3Error::Channel("writer background task gone".into()))
        }
    }

    fn finish(
        &mut self,
        translation: &[u8],
        metadata: TableMetadata,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let translation = translation.to_vec();
        let metadata_bytes = serialize_metadata(&metadata);
        let cmd_tx = self.cmd_tx.clone();
        let result_rx = self.result_rx.clone();
        async move {
            cmd_tx
                .send(WriterCmd::Finish {
                    translation,
                    metadata_bytes,
                })
                .await
                .map_err(|_| S3Error::Channel("writer background task gone".into()))?;

            // Drop the command sender so the background task knows no more
            // commands are coming after Finish.
            drop(cmd_tx);

            // Wait for the background task to complete all uploads.
            result_rx
                .recv()
                .await
                .map_err(|_| S3Error::Channel("writer result channel closed".into()))?
        }
    }
}

/// Background task that runs on the tokio runtime. Receives ciphertext chunks,
/// buffers them into parts, and uploads via `object_store` multipart API.
async fn background_writer(
    store: Arc<dyn ObjectStore>,
    root_paths: TableRootPaths,
    version_paths: TableVersionPaths,
    part_buffer_size: usize,
    cmd_rx: kanal::AsyncReceiver<WriterCmd>,
    result_tx: kanal::AsyncSender<Result<(), S3Error>>,
) {
    let result = background_writer_inner(
        &store,
        &root_paths,
        &version_paths,
        part_buffer_size,
        &cmd_rx,
    )
    .await;
    if let Err(e) = &result {
        error!(
            path = %version_paths.ciphertexts,
            %e,
            "background writer failed"
        );
    }
    if result_tx.send(result).await.is_err() {
        tracing::warn!("background writer: result channel closed, caller gone");
    }
}

/// Minimum interval between object-store upload progress lines.
const STORE_PROGRESS_PERIOD: Duration = Duration::from_secs(30);

/// Emit one object-store upload progress line.
///
/// `put` is the throughput achieved while actually inside `put_part` — the
/// store's own speed — whereas `avg` is measured against wall-clock and so is
/// additionally diluted by time spent waiting for the producer to supply data.
/// `put` well above `avg` means we are starved upstream; the two converging
/// means the store is the constraint.
fn log_store_progress(
    event: &str,
    path: &object_store::path::Path,
    parts: u64,
    bytes_put: u64,
    started: Instant,
    in_put: Duration,
) {
    let wall = started.elapsed().as_secs_f64().max(1e-3);
    let put_secs = in_put.as_secs_f64().max(1e-3);
    // The path embeds the sending peer's full hex id and the circuit index
    // (`…/{peer_hex}/{index}/versions/…`), so concurrent receives on one
    // node stay attributable to their table.
    tracing::info!(
        target: "mosaic_progress",
        phase = "table.store",
        "table.store {} path={} parts={} uploaded={:.1}GiB put={:.1}MB/s avg={:.1}MB/s \
         elapsed={:.0}s in_put={:.0}s({:.0}%)",
        event,
        path,
        parts,
        bytes_put as f64 / (1024.0 * 1024.0 * 1024.0),
        bytes_put as f64 / put_secs / 1.0e6,
        bytes_put as f64 / wall / 1.0e6,
        wall,
        in_put.as_secs_f64(),
        in_put.as_secs_f64() * 100.0 / wall,
    );
}

async fn background_writer_inner(
    store: &Arc<dyn ObjectStore>,
    root_paths: &TableRootPaths,
    version_paths: &TableVersionPaths,
    part_buffer_size: usize,
    cmd_rx: &kanal::AsyncReceiver<WriterCmd>,
) -> Result<(), S3Error> {
    // Start a multipart upload for the ciphertext object.
    let mut upload = store.put_multipart(&version_paths.ciphertexts).await?;
    let mut buffer = Vec::with_capacity(part_buffer_size);

    // Upload-side progress. Parts are uploaded one at a time (each `put_part`
    // is awaited before the next begins), so `in_put` is the true serialized
    // cost of shipping this table to the object store. When it approaches the
    // wall-clock, the store — not the peer or the CPU — is what is pacing the
    // transfer, and the backpressure surfaces upstream through the bounded
    // command channel.
    let upload_started = Instant::now();
    let mut last_log = upload_started;
    let mut parts: u64 = 0;
    let mut bytes_put: u64 = 0;
    let mut in_put = Duration::ZERO;

    loop {
        let cmd = match cmd_rx.recv().await {
            Ok(cmd) => cmd,
            Err(_) => {
                // Channel closed without Finish — abort the upload.
                upload.abort().await?;
                return Err(S3Error::StreamIo(
                    "writer dropped without calling finish".into(),
                ));
            }
        };

        match cmd {
            WriterCmd::Write(data) => {
                // Fill the buffer exactly to the part size and hand it off
                // whole, splitting incoming chunks on part boundaries. The
                // buffer never grows past its initial capacity (appending
                // past it would double the allocation, which `drain` never
                // returns), and moving it into `Bytes` avoids copying the
                // part.
                let mut data = data.as_slice();
                while !data.is_empty() {
                    let take = data.len().min(part_buffer_size - buffer.len());
                    buffer.extend_from_slice(&data[..take]);
                    data = &data[take..];

                    if buffer.len() == part_buffer_size {
                        let part =
                            std::mem::replace(&mut buffer, Vec::with_capacity(part_buffer_size));
                        let n = part.len() as u64;
                        let put_started = Instant::now();
                        upload.put_part(Bytes::from(part).into()).await?;
                        in_put += put_started.elapsed();
                        parts += 1;
                        bytes_put += n;
                    }
                }

                if last_log.elapsed() >= STORE_PROGRESS_PERIOD {
                    log_store_progress(
                        "progress",
                        &version_paths.ciphertexts,
                        parts,
                        bytes_put,
                        upload_started,
                        in_put,
                    );
                    last_log = Instant::now();
                }
            }

            WriterCmd::Finish {
                translation,
                metadata_bytes,
            } => {
                // Upload any remaining buffered ciphertext as the final part.
                if !buffer.is_empty() {
                    let final_part = std::mem::take(&mut buffer);
                    let n = final_part.len() as u64;
                    let put_started = Instant::now();
                    upload.put_part(Bytes::from(final_part).into()).await?;
                    in_put += put_started.elapsed();
                    parts += 1;
                    bytes_put += n;
                }

                // Complete the multipart upload.
                upload.complete().await?;

                log_store_progress(
                    "summary",
                    &version_paths.ciphertexts,
                    parts,
                    bytes_put,
                    upload_started,
                    in_put,
                );

                // Upload translation material as a single object under the staged version.
                store
                    .put(&version_paths.translation, Bytes::from(translation).into())
                    .await?;

                // Upload metadata as a single object under the staged version.
                store
                    .put(&version_paths.metadata, Bytes::from(metadata_bytes).into())
                    .await?;

                // Publish the immutable version by atomically replacing the live marker.
                // Readers trust only this marker when resolving the visible table version.
                store
                    .put(
                        &root_paths.committed,
                        Bytes::from(version_paths.version.clone()).into(),
                    )
                    .await?;

                return Ok(());
            }
        }
    }
}

/// Serialize [`TableMetadata`] to a fixed 64-byte format.
///
/// Layout: `output_label_ct (32B) || aes_key (16B) || public_s (16B)`
fn serialize_metadata(meta: &TableMetadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(meta.output_label_ct.as_ref());
    buf.extend_from_slice(&meta.aes_key);
    buf.extend_from_slice(&meta.public_s);
    buf
}

use std::future::Future;
