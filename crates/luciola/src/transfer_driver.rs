//! Bridge between `luciola::link::secure::SecureStream` and
//! `luciola_transfer::driver`.

use std::path::Path;
use std::time::Duration;

use luciola_proto::ChannelType;
use luciola_transfer::driver::{
    recv_file_over_transport, send_file_over_transport, TransferProgress, TransferReceipt,
    TransferTransport,
};
use luciola_transfer::{ReceiverConfig, SenderConfig, TransferError};
use tokio::sync::watch;

use crate::link::secure::SecureStream;

impl TransferTransport for SecureStream {
    async fn send_frame(&mut self, bytes: &[u8]) -> Result<(), TransferError> {
        self.send(bytes)
            .await
            .map_err(|e| TransferError::State(e.to_string()))
    }

    async fn recv_frame(&mut self, buf: &mut Vec<u8>) -> Result<(), TransferError> {
        self.recv(buf)
            .await
            .map_err(|e| TransferError::State(e.to_string()))
    }

    async fn shutdown(&mut self) -> Result<(), TransferError> {
        SecureStream::shutdown(self)
            .await
            .map_err(|e| TransferError::State(e.to_string()))
    }

    fn channel_type(&self) -> ChannelType {
        SecureStream::channel_type(self)
    }

    fn may_migrate(&self) -> bool {
        SecureStream::may_migrate(self)
    }

    async fn wait_channel_settle(&mut self, timeout: Duration) -> ChannelType {
        SecureStream::wait_channel_settle(self, timeout).await
    }
}

/// Send one file over an established [`SecureStream`] (LAN, WAN, or USB ADB).
pub async fn send_file_over_stream<F>(
    stream: SecureStream,
    file_path: &Path,
    file_name: Option<&str>,
    transfer_id: Option<&str>,
    cfg: SenderConfig,
    cancel: watch::Receiver<bool>,
    on_progress: F,
) -> Result<TransferReceipt, TransferError>
where
    F: FnMut(TransferProgress) + Send,
{
    send_file_over_transport(
        stream,
        file_path,
        file_name,
        transfer_id,
        cfg,
        cancel,
        on_progress,
    )
    .await
}

/// Receive one file over an established [`SecureStream`] into `dest_dir`.
pub async fn recv_file_over_stream<F>(
    stream: SecureStream,
    dest_dir: &Path,
    cfg: ReceiverConfig,
    quiet: Duration,
    cancel: watch::Receiver<bool>,
    on_progress: F,
) -> Result<TransferReceipt, TransferError>
where
    F: FnMut(TransferProgress) + Send,
{
    recv_file_over_transport(stream, dest_dir, cfg, quiet, cancel, on_progress).await
}
