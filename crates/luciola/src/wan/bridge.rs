//! Ordered byte-stream bridge between `SecureStream` and packet transports.
//!
//! `SecureStream` requires `AsyncRead + AsyncWrite` with **in-order** bytes
//! because its AES-256-GCM nonce is a strictly increasing counter. UDP and
//! WebSocket messaging are packet-oriented, so both WAN transports run a
//! driver task that turns packets into an ordered stream. This module is the
//! shared, transport-independent half of that adapter.
//!
//! Backpressure is explicit: the driver releases credit only when the peer
//! acknowledges (UDP) or the WebSocket sink accepts (relay) the bytes. That
//! keeps an unresponsive peer from growing an unbounded queue in memory.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Maximum bytes written but not yet released by the transport driver.
pub(crate) const MAX_UNACKED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct FlowState {
    outstanding: usize,
    waker: Option<Waker>,
}

/// Credit counter shared by a [`StreamBridge`] and its driver task.
#[derive(Default)]
pub(crate) struct Flow(Mutex<FlowState>);

impl Flow {
    /// Reserve up to `want` bytes. Returns how many may actually be written.
    pub(crate) fn take(&self, want: usize) -> usize {
        let mut state = self.0.lock().expect("flow mutex poisoned");
        let free = MAX_UNACKED_BYTES.saturating_sub(state.outstanding);
        let n = want.min(free);
        state.outstanding += n;
        n
    }

    /// Register the writer's waker for when the driver releases credit.
    pub(crate) fn park(&self, cx: &mut Context<'_>) {
        let mut state = self.0.lock().expect("flow mutex poisoned");
        state.waker = Some(cx.waker().clone());
    }

    /// The driver calls this once bytes have left the process or been ACKed.
    pub(crate) fn release(&self, n: usize) {
        let mut state = self.0.lock().expect("flow mutex poisoned");
        state.outstanding = state.outstanding.saturating_sub(n);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

/// The driver half of a newly created [`StreamBridge`].
pub(crate) struct BridgeEnds {
    /// Bytes the application wrote; an empty `Vec` is a close request.
    pub(crate) outbound_rx: UnboundedReceiver<Vec<u8>>,
    /// Ordered bytes to deliver to the application; dropping it signals EOF.
    pub(crate) inbound_tx: UnboundedSender<Vec<u8>>,
    /// Credit shared with the writer.
    pub(crate) flow: Arc<Flow>,
}

/// An ordered byte stream backed by two unbounded channels and a driver task.
///
/// Implements [`crate::link::secure::ByteStream`], so it can be handed straight
/// to `secure_handshake_client` / `secure_handshake_server`.
pub(crate) struct StreamBridge {
    outbound: UnboundedSender<Vec<u8>>,
    inbound: UnboundedReceiver<Vec<u8>>,
    pending: Vec<u8>,
    pending_off: usize,
    flow: Arc<Flow>,
    closed: bool,
}

/// Create a bridge and the endpoints its driver must own.
pub(crate) fn bridge_pair() -> (StreamBridge, BridgeEnds) {
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let flow = Arc::new(Flow::default());
    (
        StreamBridge {
            outbound: outbound_tx,
            inbound: inbound_rx,
            pending: Vec::new(),
            pending_off: 0,
            flow: flow.clone(),
            closed: false,
        },
        BridgeEnds {
            outbound_rx,
            inbound_tx,
            flow,
        },
    )
}

impl AsyncRead for StreamBridge {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending_off < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.pending_off);
                buf.put_slice(&this.pending[this.pending_off..this.pending_off + n]);
                this.pending_off += n;
                return Poll::Ready(Ok(()));
            }
            match this.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.pending = chunk;
                    this.pending_off = 0;
                }
                // Driver dropped the sender: clean EOF for the secure channel.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for StreamBridge {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wan transport already shut down",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = this.flow.take(buf.len());
        if n == 0 {
            this.flow.park(cx);
            return Poll::Pending;
        }
        if this.outbound.send(buf[..n].to_vec()).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wan transport driver stopped",
            )));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            let _ = this.outbound.send(Vec::new());
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::task::noop_waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bridge_roundtrips_bytes_through_a_driver() {
        let (mut app, mut ends) = bridge_pair();
        let driver = tokio::spawn(async move {
            while let Some(bytes) = ends.outbound_rx.recv().await {
                if bytes.is_empty() {
                    break;
                }
                let n = bytes.len();
                ends.flow.release(n);
                if ends.inbound_tx.send(bytes).is_err() {
                    break;
                }
            }
        });

        app.write_all(b"ordered bytes").await.unwrap();
        let mut out = vec![0u8; 13];
        app.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ordered bytes");
        app.shutdown().await.unwrap();
        driver.await.unwrap();
    }

    #[test]
    fn writer_blocks_when_credit_is_exhausted_and_wakes_on_release() {
        let (mut app, ends) = bridge_pair();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut app);

        // `poll_write` never returns more than the free credit, so fill it in
        // chunks and confirm the next poll is Pending (not a silent drop).
        let mut remaining = MAX_UNACKED_BYTES;
        let block = vec![7u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(block.len());
            match pinned.as_mut().poll_write(&mut cx, &block[..want]) {
                Poll::Ready(Ok(n)) => remaining -= n,
                other => panic!("unexpected poll while credit remained: {other:?}"),
            }
        }
        assert!(matches!(
            pinned.as_mut().poll_write(&mut cx, b"x"),
            Poll::Pending
        ));

        ends.flow.release(64 * 1024);
        assert!(matches!(
            pinned.as_mut().poll_write(&mut cx, b"x"),
            Poll::Ready(Ok(1))
        ));
    }
}
