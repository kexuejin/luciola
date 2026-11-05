use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::Waker;
use std::time::Instant;

use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tracing::warn;

use super::*;

// ---------------------------------------------------------------- 内部状态

/// 通道模式：流式（TCP 语义）或数据报（UDP 语义，DATA 帧 = 一个数据报）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanMode {
    /// 流式通道（TCP 语义，有序字节流）。
    Stream,
    /// 数据报通道（UDP 语义，一帧 = 一个数据报）。
    Datagram,
}

/// 队列内部：入站通道消息。
#[derive(Debug)]
pub(crate) enum MuxInbound {
    Data(Vec<u8>),
    Eof,
    /// 对端 CLOSE(ch) —— reason=0 视为读端正常结束。
    Close(u8),
    /// 会话终止：所有通道同步置错。
    SessionDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Pending,
    Active,
}

/// open() 等待 OPEN_ACK 的结果：Ok(0 经 grant) / Err((status, detail))。
type AckOutcome = Result<(), (u8, Option<String>)>;

/// 逐通道流控状态（v2 WINDOW）。会话与 MuxStream/MuxDatagram 共享。
pub(crate) struct FlowState {
    /// 已发出但未获对端 WINDOW credit 确认的字节数。与 waker 同锁：
    /// poll_write 的「检查窗口 + 登记 waker」与 reader 的「减 credit + 唤醒」互斥。
    pub(crate) send: StdMutex<SendWindow>,
    /// 已消费、待上报给对端的字节数（credit 阈值触发 WINDOW 帧）。
    pub(crate) unacked: AtomicU64,
    /// 异步等待方（send_datagram）的唤醒器。
    pub(crate) wake: Notify,
    /// 最近活动时刻（epoch 毫秒）；idle reaper 依据。
    pub(crate) last_active_ms: AtomicU64,
    /// 已投递到通道暂存队列、应用（MuxStream/MuxDatagram）尚未读走的字节数。
    /// read 任务据此执行 `Inner::inbound_budget` 的字节预算：暂存队列本身无界，
    /// 但内存仍按窗口量级有界，超限只拆该通道（绝不阻塞 read 任务）。
    pub(crate) queued_in: AtomicUsize,
}

#[derive(Default)]
pub(crate) struct SendWindow {
    pub(crate) outstanding: u64,
    pub(crate) waker: Option<Waker>,
}

impl FlowState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            send: StdMutex::new(SendWindow::default()),
            unacked: AtomicU64::new(0),
            wake: Notify::new(),
            last_active_ms: AtomicU64::new(0),
            queued_in: AtomicUsize::new(0),
        })
    }

    /// 应用读走 n 字节：释放通道入站预算额度（饱和减，不 panic）。
    ///
    /// 用 compare_exchange 循环而不是 `fetch_update`：后者在较新的 std 里已
    /// 被重命名/弃用，而本仓库 CI 用 latest stable、开发机可能是旧版本，
    /// 两边都要能无警告编译。
    pub(crate) fn release_inbound(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut cur = self.queued_in.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(n);
            match self.queued_in.compare_exchange_weak(
                cur,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// peer_v2 证明时刻的钳制：证明前未执行窗口，outstanding 可能已超限。
    pub(crate) fn clamp(&self, window: u64) {
        let mut s = self.send.lock().unwrap();
        s.outstanding = s.outstanding.min(window);
    }

    pub(crate) fn touch(&self, now_ms: u64) {
        self.last_active_ms.store(now_ms, Ordering::Relaxed);
    }

    /// 通道/会话终止：唤醒所有等窗口的写方（park 的 poll_write waker 与
    /// send_datagram 的 Notify 等待者）。漏掉 waker 会让写方在窗口耗尽 +
    /// 通道死亡的组合下永久挂起。
    pub(crate) fn kill(&self) {
        let w = self.send.lock().unwrap().waker.take();
        if let Some(w) = w {
            w.wake();
        }
        self.wake.notify_waiters();
    }
}

pub(crate) struct Entry {
    pub(crate) state: State,
    pub(crate) mode: ChanMode,
    /// 有界帧队列（容量 `channel_queue_frames`），由本通道的转发任务写入、
    /// 应用侧读走。read 任务不直接触碰它，因此队列满只会堵住该通道的转发任务。
    pub(crate) in_tx: mpsc::Sender<MuxInbound>,
    /// read 任务 → 本通道转发任务的暂存队列。无界，但读任务按
    /// `Inner::inbound_budget` 的字节预算入账，内存有界；加这一跳的原因见
    /// `deliver` 文档（共享 read 任务绝不能被单通道队列堵住）。
    pub(crate) staging_tx: mpsc::UnboundedSender<MuxInbound>,
    /// 通道与 MuxStream/MuxDatagram 共享：置位后 poll_read/poll_write 直接报错。
    pub(crate) dead: Arc<AtomicBool>,
    /// 流控状态（v2）。
    pub(crate) flow: Arc<FlowState>,
    /// 仅发起方 pending 时持有（open()/open_datagram() 的 oneshot 另一端）。
    pub(crate) ack: Option<oneshot::Sender<AckOutcome>>,
}

pub(crate) struct Inner {
    pub(crate) cfg: MuxConfig,
    pub(crate) role: Role,
    pub(crate) table: StdMutex<HashMap<u32, Entry>>,
    /// Initiator 分配奇数 ch_id（1,3,5,…），Responder 分配偶数（2,4,6,…，v2）；
    /// 单调不复用（D8）。
    pub(crate) next_ch: AtomicU32,
    pub(crate) alive: AtomicBool,
    /// 对端已证明 v2 能力（收到过 PING/PONG/WINDOW 之一）。证明前：偶数通道帧
    /// 仍按 v1 判违规、本端（Responder）不执行窗口、Responder 不得发 OPEN。
    pub(crate) peer_v2: AtomicBool,
    /// 会话级 CLOSE(ch 0) 由对端线帧触发（对端主动关闭）。传输层 FIN/错误
    /// 直接 terminate 不置位——上层（CLI 监督循环）据此区分"对端关闭 → 优雅退出"与
    /// "链路断开 → 退避重建"（T2 链路引导契约）。
    pub(crate) peer_close: AtomicBool,
    pub(crate) opened_total: AtomicU64,
    pub(crate) ctrl_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) data_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) open_req_tx: mpsc::Sender<OpenRequest>,
    pub(crate) open_req_rx: AsyncMutex<Option<mpsc::Receiver<OpenRequest>>>,
    /// 会话终止原因；None = 存活。首次 terminate 生效（幂等）。
    pub(crate) term: watch::Sender<Option<u8>>,
    /// 队列满时延迟发送的通道控制帧（EOF/drop-CLOSE/WINDOW credit）。
    /// 统一队列被 DATA 背压占满时 try_send 会失败——半关闭帧或 credit 丢失会让
    /// 对端永久等待，故转延迟队列补发。
    pub(crate) deferred_ctrl: StdMutex<VecDeque<Vec<u8>>>,
    /// 延迟补发任务是否在跑。与 deferred_ctrl 同锁读写：单任务串行保证同通道保序。
    pub(crate) defer_active: AtomicBool,
    /// 会话所在 tokio 运行时（start 在 runtime 上下文内调用——调度契约，lib.rs 文档）。
    pub(crate) handle: tokio::runtime::Handle,
    /// 会话起始时刻（Idle/keepalive 的毫秒时钟基准）。
    pub(crate) epoch: Instant,
    /// 最近一次从 wire 收到帧的时刻（epoch 毫秒；reader 更新）。
    pub(crate) last_recv_ms: AtomicU64,
    /// 最近一次向 wire 写出帧的时刻（epoch 毫秒；writer 更新）。
    pub(crate) last_send_ms: AtomicU64,
    /// PING nonce 计数器（探测/周期 PING 用；无加密意义）。
    pub(crate) ping_counter: AtomicU64,
}

pub(crate) fn now_ms(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}

impl Inner {
    /// 会话级终止（§1.3）：置 alive=false（首触发者生效）→ 逐通道拆除并
    /// 唤醒 accept_open/open/MuxStream → 由 writer 发出最终 CLOSE(reason, ch 0) 后关闭写半区。
    pub(crate) fn terminate(&self, reason: u8) {
        if !self.alive.swap(false, Ordering::SeqCst) {
            return; // 已终止：幂等，避免 CLOSE 循环
        }
        let mut table = self.table.lock().unwrap();
        for (_, entry) in table.drain() {
            entry.dead.store(true, Ordering::SeqCst);
            let _ = entry.in_tx.try_send(MuxInbound::SessionDown);
            // entry.ack 被 drop → open() 收到 RecvError → SessionClosed
            entry.flow.kill();
        }
        drop(table);
        self.term.send_replace(Some(reason));
    }

    /// 可靠发送一条通道控制帧：优先直接入队；队列满则转入延迟队列，由唯一的
    /// 串行任务按入队顺序补发（同一通道先 EOF 后 CLOSE 的顺序不倒，跨通道顺序
    /// 无约束）。仅依赖 std Mutex 短临界区，绝不持锁跨 await。
    pub(crate) fn defer_ctrl(self: &Arc<Self>, frame: Vec<u8>) {
        {
            let mut q = self.deferred_ctrl.lock().unwrap();
            q.push_back(frame);
            if self.defer_active.load(Ordering::SeqCst) {
                return; // 已有补发任务在跑，它会取走新帧
            }
            self.defer_active.store(true, Ordering::SeqCst);
        }
        let inner = self.clone();
        self.handle.spawn(async move {
            loop {
                let frame = {
                    let mut q = inner.deferred_ctrl.lock().unwrap();
                    match q.pop_front() {
                        Some(f) => f,
                        None => {
                            inner.defer_active.store(false, Ordering::SeqCst);
                            return; // 清空后在锁内置位：pusher 随后必然看到 false 自行拉起
                        }
                    }
                }; // 释放锁后再 await
                if inner.ctrl_tx.send(frame).await.is_err() {
                    let mut q = inner.deferred_ctrl.lock().unwrap();
                    q.clear();
                    inner.defer_active.store(false, Ordering::SeqCst);
                    return; // writer 已停（会话结束）：对端随之终止，无需补发
                }
            }
        });
    }

    /// 对端 v2 能力证明（首次生效）：放行偶数通道帧、Responder 发 OPEN、
    /// 启用窗口执行（钳制证明前已积累的 outstanding）。
    pub(crate) fn set_peer_v2(&self) {
        if self.peer_v2.swap(true, Ordering::SeqCst) {
            return;
        }
        let window = self.cfg.window_size as u64;
        let table = self.table.lock().unwrap();
        for entry in table.values() {
            entry.flow.clamp(window);
        }
    }

    /// 单通道入站字节预算：已投递、应用尚未读走的字节上限。
    ///
    /// v2 对端的发送量受窗口约束（应用读走数据才回 WINDOW credit，故
    /// queued ≤ outstanding ≤ 对端 window），加一帧余量即可覆盖同配置对端的
    /// 全部在途数据——诚实对端永不触发。v1 对端没有窗口，超出即按 §1.4
    /// 兜底只拆该通道（旧实现是先把整条会话的 read 任务堵住再拆，这正是要
    /// 修掉的级联停顿）。
    ///
    /// 窗口不在线上协商（各端用自己的 `window_size`）：对端把窗口配得远大于
    /// 本端时，本端会在预算处拆掉该通道并告警；旧实现同样会在帧队列打满后
    /// 拆，且先堵住整条会话，所以这里不会更差。
    pub(crate) fn inbound_budget(&self) -> usize {
        self.cfg.window_size.saturating_add(self.cfg.max_data_frame)
    }

    /// 为通道启动站内转发任务（见 [`channel_forwarder`]）：read 任务只入暂存
    /// 队列，有界队列与 stall 判定都发生在该通道自己的任务里。
    pub(crate) fn spawn_channel_forwarder(
        self: &Arc<Self>,
        ch_id: u32,
        dead: Arc<AtomicBool>,
        staging: mpsc::UnboundedReceiver<MuxInbound>,
        in_tx: mpsc::Sender<MuxInbound>,
    ) {
        let inner = self.clone();
        let term_rx = self.term.subscribe();
        self.handle.spawn(async move {
            channel_forwarder(inner, ch_id, dead, staging, in_tx, term_rx).await;
        });
    }
}

/// 若表内条目仍是 dead 指向的那一个，则移除并置位 dead（可选向通道队列推一条终态消息）。
///
/// 终态消息走暂存队列：与已投递的 DATA 保序（同通道先 DATA 后 EOF/CLOSE 的顺序
/// 不倒），且不依赖有界队列此刻是否有空位。
pub(crate) fn remove_entry(
    inner: &Inner,
    ch_id: u32,
    dead: &Arc<AtomicBool>,
    push: Option<MuxInbound>,
) {
    let mut table = inner.table.lock().unwrap();
    let is_same = table
        .get(&ch_id)
        .map(|e| Arc::ptr_eq(&e.dead, dead))
        .unwrap_or(false);
    if is_same {
        if let Some(entry) = table.remove(&ch_id) {
            entry.dead.store(true, Ordering::SeqCst);
            if let Some(msg) = push {
                let _ = entry.staging_tx.send(msg);
            }
            entry.flow.kill();
        }
    }
}

// ---------------------------------------------------------------- OpenRequest

/// accept_open() 返回的待决请求（§2.2）。grant/deny 至少调用一个；
/// 未答复即 Drop → 自动 deny(2)（open_timeout 到期对端会收到终态帧）。
pub struct OpenRequest {
    /// 对端请求拨号的目标。
    pub target: DialTarget,
    /// 对端分配的通道 ID。
    pub ch_id: u32,
    /// true = 数据报通道（DOPEN，UDP 会话映射）：用 grant_datagram() 应答。
    pub datagram: bool,
    pub(crate) rx: Option<mpsc::Receiver<MuxInbound>>,
    pub(crate) inner: Arc<Inner>,
    pub(crate) answered: bool,
}

impl fmt::Debug for OpenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRequest")
            .field("target", &self.target)
            .field("ch_id", &self.ch_id)
            .field("datagram", &self.datagram)
            .field("answered", &self.answered)
            .finish()
    }
}

impl OpenRequest {
    /// 允许流式请求：先把通道置 Active，再回 OPEN_ACK(0)（§1.3 顺序），返回已激活的流。
    /// 数据报请求打 grant() → ModeMismatch（改用 grant_datagram）。
    pub async fn grant(mut self) -> Result<MuxStream, MuxError> {
        let rx = self.activate().await?;
        if self.datagram {
            return Err(MuxError::ModeMismatch);
        }
        let ch_id = self.ch_id;
        let inner = self.inner.clone();
        let dead = entry_dead_marker(&inner, ch_id);
        Ok(MuxStream::new(ch_id, inner, rx, dead))
    }

    /// 允许数据报请求（v2 UDP 会话映射）：先置 Active 再回 OPEN_ACK(0)，返回数据报端。
    pub async fn grant_datagram(mut self) -> Result<MuxDatagram, MuxError> {
        let rx = self.activate().await?;
        if !self.datagram {
            return Err(MuxError::ModeMismatch);
        }
        let ch_id = self.ch_id;
        let inner = self.inner.clone();
        let dead = entry_dead_marker(&inner, ch_id);
        Ok(MuxDatagram::new(ch_id, inner, rx, dead))
    }

    /// grant/grant_datagram 共用：置 Active → 写 ACK(0)。返回通道队列接收端。
    async fn activate(&mut self) -> Result<mpsc::Receiver<MuxInbound>, MuxError> {
        self.answered = true;
        let inner = &self.inner;
        if !inner.alive.load(Ordering::SeqCst) {
            return Err(MuxError::SessionClosed);
        }
        let ch_id = self.ch_id;
        let dead = {
            let mut table = inner.table.lock().unwrap();
            match table.get_mut(&ch_id) {
                Some(entry) if entry.state == State::Pending => {
                    entry.state = State::Active; // 先 Active，再写 ACK(0)
                    entry.dead.clone()
                }
                _ => return Err(MuxError::ChannelClosed),
            }
        };
        let frame = encode_frame(T_ACK, ch_id, &[AckStatus::OK]);
        if inner.ctrl_tx.send(frame).await.is_err() {
            remove_entry(inner, ch_id, &dead, None);
            return Err(MuxError::SessionClosed);
        }
        let dead_marker = dead;
        if let Some(entry) = inner.table.lock().unwrap().get(&ch_id) {
            if Arc::ptr_eq(&entry.dead, &dead_marker) {
                entry.flow.touch(now_ms(inner.epoch));
            }
        }
        self.rx.take().ok_or(MuxError::ChannelClosed)
    }

    /// 拒绝请求或拨号失败：回 OPEN_ACK(status) 终态帧（可附 detail），
    /// 不产生通道端，先回收通道再发帧、不补发 CLOSE。
    pub async fn deny(mut self, status: u8, detail: Option<String>) -> Result<(), MuxError> {
        if status == AckStatus::OK || status > AckStatus::BAD_TARGET {
            // 非法状态：按已答复处理并回收通道——既不回帧、也不触发 Drop 自动 deny(2)
            self.answered = true;
            remove_entry(
                &self.inner,
                self.ch_id,
                &entry_dead_marker(&self.inner, self.ch_id),
                None,
            );
            return Err(MuxError::InvalidAckStatus(status));
        }
        self.answered = true;
        let inner = &self.inner;
        let ch_id = self.ch_id;
        // 条目可能已被 terminate 排空：entry_dead_marker 在无条目时给一个
        // 永不匹配的死 Arc，等价 no-op。
        remove_entry(inner, ch_id, &entry_dead_marker(inner, ch_id), None);
        let payload = encode_ack_payload(status, detail.as_deref());
        match inner
            .ctrl_tx
            .send(encode_frame(T_ACK, ch_id, &payload))
            .await
        {
            Ok(()) => Ok(()),
            Err(_) => Err(MuxError::SessionClosed),
        }
    }
}

impl Drop for OpenRequest {
    fn drop(&mut self) {
        if self.answered {
            return;
        }
        let ch_id = self.ch_id;
        {
            let mut table = self.inner.table.lock().unwrap();
            table.remove(&ch_id);
        }
        let _ = self
            .inner
            .ctrl_tx
            .try_send(encode_frame(T_ACK, ch_id, &[AckStatus::DIAL_FAILED]));
        warn!("OpenRequest(ch={ch_id}) dropped unanswered — auto deny(ACK_DIAL_FAILED)");
    }
}

// deny() 需要在未持有 dead 句柄时按 ch_id 回收：条目可能在 grant/deny 之前
// 已被 terminate 排空，此时 remove-by-ch 即可；为保持 remove_entry 的
// same-entry 判定，这里取一次当前 dead（若无条目则用一个新 Arc 永不匹配，等价 no-op）。
pub(crate) fn entry_dead_marker(inner: &Inner, ch_id: u32) -> Arc<AtomicBool> {
    let table = inner.table.lock().unwrap();
    table
        .get(&ch_id)
        .map(|e| e.dead.clone())
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
}
