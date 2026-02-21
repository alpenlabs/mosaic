//! S3-backed [`TableWriter`] implementation.
//!
//! Streams ciphertext data to the background tokio runtime which performs
//! multipart uploads via `object_store`. Translation material and metadata
//! are uploaded as separate objects during [`finish`](S3TableWriter::finish).

use std::sync::Arc;

use bytes::Bytes;
use mosaic_storage_api::table_store::{TableMetadata, TableWriter};
use object_store::ObjectStore;

use crate::PART_BUFFER_SIZE;
use crate::error::S3Error;
use crate::paths::TablePaths;

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
/// buffer exceeds [`PART_BUFFER_SIZE`]. Translation material and metadata are
/// uploaded as separate objects on [`finish`](Self::finish).
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
        paths: TablePaths,
    ) -> Result<Self, S3Error> {
        let (cmd_tx, cmd_rx) = kanal::bounded_async(crate::STREAM_CHANNEL_CAPACITY);
        let (result_tx, result_rx) = kanal::bounded_async(1);

        rt_handle.spawn(background_writer(store, paths, cmd_rx, result_tx));

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
        self,
        translation: &[u8],
        metadata: TableMetadata,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let translation = translation.to_vec();
        let metadata_bytes = serialize_metadata(&metadata);
        let cmd_tx = self.cmd_tx;
        let result_rx = self.result_rx;
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
    paths: TablePaths,
    cmd_rx: kanal::AsyncReceiver<WriterCmd>,
    result_tx: kanal::AsyncSender<Result<(), S3Error>>,
) {
    let result = background_writer_inner(&store, &paths, &cmd_rx).await;
    let _ = result_tx.send(result).await;
}

async fn background_writer_inner(
    store: &Arc<dyn ObjectStore>,
    paths: &TablePaths,
    cmd_rx: &kanal::AsyncReceiver<WriterCmd>,
) -> Result<(), S3Error> {
    // Start a multipart upload for the ciphertext object.
    let mut upload = store.put_multipart(&paths.ciphertexts).await?;
    let mut buffer = Vec::with_capacity(PART_BUFFER_SIZE);

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
                buffer.extend_from_slice(&data);

                // Upload complete parts when the buffer is large enough.
                while buffer.len() >= PART_BUFFER_SIZE {
                    let part: Vec<u8> = buffer.drain(..PART_BUFFER_SIZE).collect();
                    upload.put_part(Bytes::from(part).into()).await?;
                }
            }

            WriterCmd::Finish {
                translation,
                metadata_bytes,
            } => {
                // Upload any remaining buffered ciphertext as the final part.
                if !buffer.is_empty() {
                    let final_part = std::mem::take(&mut buffer);
                    upload.put_part(Bytes::from(final_part).into()).await?;
                }

                // Complete the multipart upload.
                upload.complete().await?;

                // Upload translation material as a single object.
                store
                    .put(&paths.translation, Bytes::from(translation).into())
                    .await?;

                // Upload metadata as a single object.
                store
                    .put(&paths.metadata, Bytes::from(metadata_bytes).into())
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
