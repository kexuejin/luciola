use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::debug;

use super::*;

// ---------------------------------------------------------------- MuxStream

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Running,
    Eof,
    Reset(&'static str),
}

/// 单条流式 mux 通道：实现 tokio AsyncRead + AsyncWrite（§2.2）。
pub struct MuxStream {
    ch_id: u32,
    inner: Arc<Inner>,
    rx: mpsc::Receiver<MuxInbound>,
    dead: Arc<AtomicBool>,
    flow: Arc<FlowState>,
    data: PollSender<Vec<u8>>,
    read_buf: Option<(Vec<u8>, usize)>,
    read_state: ReadState,
    write_eof: bool,
    got_close: bool,
}

impl MuxStream {
    pub(crate) fn new(
        ch_id: u32,
        inner: Arc<Inner>,
        rx: mpsc::Receiver<MuxInbound>,
        dead: Arc<AtomicBool>,
    ) -> Self {
        let flow = {
            let table = inner.table.lock().unwrap();
            table
                .get(&ch_id)
                .filter(|e| Arc::ptr_eq(&e.dead, &dead))
                .map(|e| e.flow.clone())
                .unwrap_or_else(FlowState::new)
        };
        let data = PollSender::new(inner.data_tx.clone());
        Self {
            ch_id,
            inner,
            rx,
            dead,
            flow,
            data,
            read_buf: None,
            read_state: ReadState::Running,
            write_eof: false,
            got_close: false,
        }
    }

    /// 通道 ID（奇数 = Initiator 发起，偶数 = Responder 发起的 remote forward；D8）。
    pub fn ch_id(&self) -> u32 {
        self.ch_id
    }

    /// 通道是否已被拆除（正常 EOF/CLOSE、停顿断流或会话终止）。
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// 应用读走 n 字节：释放入站预算 + 上报对端窗口 credit（v2）。
    fn credit(&self, n: usize) {
        self.flow.release_inbound(n);
        send_credit(&self.inner, self.ch_id, &self.flow, n);
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 上一帧 DATA 的剩余字节（帧可大于本次读缓冲）
        if let Some((data, off)) = &mut this.read_buf {
            if *off < data.len() {
                let n = buf.remaining().min(data.len() - *off);
                buf.put_slice(&data[*off..*off + n]);
                *off += n;
                let done = *off >= data.len();
                if done {
                    this.read_buf = None;
                }
                this.credit(n);
                return Poll::Ready(Ok(()));
            }
            this.read_buf = None;
        }
        match this.read_state {
            ReadState::Eof => return Poll::Ready(Ok(())),
            ReadState::Reset(why) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, why)))
            }
            ReadState::Running => {}
        }
        loop {
            match this.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    // 队列发送端全部消失：条目已被回收
                    this.read_state = ReadState::Reset("channel closed");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "channel closed",
                    )));
                }
                Poll::Ready(Some(msg)) => match msg {
                    MuxInbound::Data(bytes) => {
                        if bytes.is_empty() {
                            continue;
                        }
                        // 立刻出数：不能 continue 回去继续 poll_recv——那会
                        // 覆盖缓冲里的上一帧，或带着已缓冲数据返回 Pending
                        // （单帧场景 = 永久卡死直到下一帧到来）。
                        let n = buf.remaining().min(bytes.len());
                        buf.put_slice(&bytes[..n]);
                        if n < bytes.len() {
                            this.read_buf = Some((bytes, n));
                        }
                        this.credit(n);
                        return Poll::Ready(Ok(()));
                    }
                    MuxInbound::Eof => {
                        this.read_state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    MuxInbound::Close(CloseReason::NORMAL) => {
                        // 对端正常关通道：读端视为 EOF；写端由 dead 保护。
                        this.got_close = true;
                        this.read_state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    MuxInbound::Close(reason) => {
                        this.got_close = true;
                        let why: &'static str = match reason {
                            CloseReason::PROTOCOL_VIOLATION => {
                                "channel closed by peer (protocol violation)"
                            }
                            CloseReason::UPSTREAM_RESET => "upstream reset",
                            CloseReason::SESSION_SHUTDOWN => "session shutdown",
                            _ => "channel closed",
                        };
                        this.read_state = ReadState::Reset(why);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            why,
                        )));
                    }
                    MuxInbound::SessionDown => {
                        this.read_state = ReadState::Reset("session shutdown");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "session shutdown",
                        )));
                    }
                },
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_eof {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after poll_shutdown",
            )));
        }
        if this.dead.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "channel closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 部分写（§2.2）：每次最多 max_data_frame 字节；v2 对端再受逐通道窗口
        // 约束（outstanding ≥ window_size 时挂起，credit 到达唤醒）。
        //
        // 顺序铁律：先 poll_reserve 再做窗口门控。反过来（先记 outstanding 再
        // reserve）在 reserve 返回 Pending 时会留下幻影计数——重试时再次累加，
        // 窗口被从未发出的字节永久占满（credit 只确认真实发出的数据）。
        // 先 reserve 则 Pending 无副作用；Ready 持有许可后再查窗口，挂起不丢
        // 许可（下次 poll_reserve 立即 Ready），credit 唤醒后照常 send_item。
        let n0 = buf.len().min(this.inner.cfg.max_data_frame);
        match this.data.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "session writer stopped",
            ))),
            Poll::Ready(Ok(())) => {
                let n = if this.inner.peer_v2.load(Ordering::SeqCst) {
                    let window = this.inner.cfg.window_size as u64;
                    let mut s = this.flow.send.lock().unwrap();
                    let avail = window.saturating_sub(s.outstanding);
                    if avail == 0 {
                        s.waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    let n = n0.min(avail as usize);
                    s.outstanding += n as u64;
                    n
                } else {
                    n0
                };
                this.flow.touch(now_ms(this.inner.epoch));
                let frame = encode_frame(T_DATA, this.ch_id, &buf[..n]);
                match this.data.send_item(frame) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "session writer stopped",
                    ))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_eof {
            return Poll::Ready(Ok(()));
        }
        this.write_eof = true;
        if this.dead.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }
        let eof = encode_frame(T_EOF, this.ch_id, &[]);
        if this.inner.ctrl_tx.try_send(eof.clone()).is_err() {
            // 统一队列被 DATA 背压占满：延迟补发，半关闭帧不可丢（否则对端拷贝悬挂）。
            debug!("queue full for ch {} EOF, deferring", this.ch_id);
            this.inner.defer_ctrl(eof);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        // 正常拆除 = 双向 EOF 完成，或已收到对端 CLOSE；否则补发 CLOSE(0)（§2.2）。
        let bidirectional_done = self.read_state == ReadState::Eof && self.write_eof;
        if self.dead.load(Ordering::SeqCst) || bidirectional_done || self.got_close {
            return;
        }
        let close = encode_frame(T_CLOSE, self.ch_id, &[CloseReason::NORMAL]);
        if self.inner.ctrl_tx.try_send(close.clone()).is_err() {
            debug!("queue full for ch {} drop-CLOSE, deferring", self.ch_id);
            self.inner.defer_ctrl(close);
        }
    }
}

// ---------------------------------------------------------------- MuxDatagram

/// 单条数据报 mux 通道（v2 UDP 会话映射）：每个 DATA 帧携带一个 UDP 数据报，
/// 边界保留。0 长数据报在 wire 上不可表示（空 DATA 帧被丢弃，记录在案）。
pub struct MuxDatagram {
    ch_id: u32,
    inner: Arc<Inner>,
    rx: mpsc::Receiver<MuxInbound>,
    dead: Arc<AtomicBool>,
    flow: Arc<FlowState>,
}

impl MuxDatagram {
    pub(crate) fn new(
        ch_id: u32,
        inner: Arc<Inner>,
        rx: mpsc::Receiver<MuxInbound>,
        dead: Arc<AtomicBool>,
    ) -> Self {
        let flow = {
            let table = inner.table.lock().unwrap();
            table
                .get(&ch_id)
                .filter(|e| Arc::ptr_eq(&e.dead, &dead))
                .map(|e| e.flow.clone())
                .unwrap_or_else(FlowState::new)
        };
        Self {
            ch_id,
            inner,
            rx,
            dead,
            flow,
        }
    }

    /// 通道 ID（奇偶规则同 MuxStream；D8）。
    pub fn ch_id(&self) -> u32 {
        self.ch_id
    }

    /// 通道是否已被拆除。
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// 发送一个数据报。> MAX_DATA_FRAME 报 DatagramTooLarge（UDP 数据报上限
    /// 65507 < 64KiB，正常 socket 不会触发）；窗口耗尽时等待 credit。
    pub async fn send_datagram(&self, bytes: &[u8]) -> Result<(), MuxError> {
        if bytes.len() > MAX_DATA_FRAME {
            return Err(MuxError::DatagramTooLarge(bytes.len()));
        }
        if bytes.is_empty() {
            return Ok(()); // 空 DATA 帧 wire 上不可表示；静默成功（对端等价于丢包）
        }
        if self.dead.load(Ordering::SeqCst) {
            return Err(MuxError::ChannelClosed);
        }
        let window = self.inner.cfg.window_size as u64;
        if self.inner.peer_v2.load(Ordering::SeqCst) {
            let mut term_rx = self.inner.term.subscribe();
            loop {
                // notified() 必须先于 dead/窗口检查注册（enable()），否则 kill()
                // 的 notify_waiters()（不存 permit）落在"检查之后、注册之前"时
                // 唤醒丢失，写方在窗口耗尽 + 通道拆除的组合下永久挂起。注册之后
                // 任何一次 kill() 要么唤醒本任务，要么发生在 enable 之前而 dead
                // 标志在下面的检查里已经可见。
                let notified = self.flow.wake.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.dead.load(Ordering::SeqCst) {
                    // 等窗口期间通道被对端/本地拆除（CLOSE/stall/回收）：
                    // credit 永不再来，必须干净报错而不是等到会话结束。
                    return Err(MuxError::ChannelClosed);
                }
                {
                    let mut s = self.flow.send.lock().unwrap();
                    if s.outstanding < window {
                        s.outstanding += bytes.len() as u64;
                        break;
                    }
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = term_rx.changed() => return Err(MuxError::SessionClosed),
                }
            }
        }
        self.flow.touch(now_ms(self.inner.epoch));
        let frame = encode_frame(T_DATA, self.ch_id, bytes);
        match self.inner.data_tx.send(frame).await {
            Ok(()) => Ok(()),
            Err(_) => Err(MuxError::SessionClosed),
        }
    }

    /// 接收下一个数据报；None = 通道已拆（EOF/CLOSE/会话终止）。
    pub async fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        match self.rx.recv().await {
            Some(MuxInbound::Data(bytes)) => {
                self.flow.release_inbound(bytes.len());
                send_credit(&self.inner, self.ch_id, &self.flow, bytes.len());
                self.flow.touch(now_ms(self.inner.epoch));
                Some(bytes)
            }
            Some(MuxInbound::Eof) => None,
            Some(MuxInbound::Close(CloseReason::NORMAL)) => None,
            Some(MuxInbound::Close(_)) => None,
            Some(MuxInbound::SessionDown) => None,
            None => None,
        }
    }
}

impl Drop for MuxDatagram {
    fn drop(&mut self) {
        if self.dead.load(Ordering::SeqCst) {
            return;
        }
        let close = encode_frame(T_CLOSE, self.ch_id, &[CloseReason::NORMAL]);
        if self.inner.ctrl_tx.try_send(close.clone()).is_err() {
            self.inner.defer_ctrl(close);
        }
    }
}
