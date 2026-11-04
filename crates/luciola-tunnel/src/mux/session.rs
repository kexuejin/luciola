use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use luciola::link::secure::SecureStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{mpsc, oneshot, watch};

use super::*;

// ---------------------------------------------------------------- MuxSession

/// 一条 SecureStream 上的 mux 会话。
///
/// start() 内部 spawn reader/writer（以及 keepalive / idle reaper）任务，
/// 必须在 tokio runtime 上下文中调用。会话结束有四条路径：连接断开、对端
/// CLOSE(ch 0)、本端 shutdown()、v2 对端 keepalive 静默超时；本端主动结束请
/// 显式调用 shutdown()（丢弃 MuxSession 本身不会断开通道）。
#[derive(Clone)]
pub struct MuxSession {
    inner: Arc<Inner>,
}

impl MuxSession {
    /// 在 SecureStream 上启动 mux 会话（spec §2.2：非 async，内部 spawn 任务）。
    pub fn start(stream: SecureStream, role: Role, cfg: MuxConfig) -> Self {
        let cfg = cfg.sanitized();
        let (recv, send) = stream.into_split();
        let ctrl_cap = cfg.max_channels.saturating_mul(4).max(1) + 32; // ≥ max×4+32（§1.4）
        let data_cap = (cfg.max_channels.saturating_mul(cfg.channel_queue_frames)).max(16);
        // 单一 FIFO：OPEN/ACK/DATA/EOF/CLOSE 全部同队列，严格按入队顺序出队。
        // 双队列时 writer 偏向 ctrl 会让 EOF/CLOSE 越过前面已排队的 DATA（重排）。
        // 容量取两者最大：数据有突发空间；控制帧在满时走 defer_ctrl 延迟补发（不可丢）。
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<Vec<u8>>(ctrl_cap.max(data_cap));
        let data_tx = ctrl_tx.clone();
        let (req_tx, req_rx) = mpsc::channel::<OpenRequest>(cfg.max_channels.max(4));
        let (term, _) = watch::channel::<Option<u8>>(None);
        let inner = Arc::new(Inner {
            role,
            cfg,
            table: StdMutex::new(HashMap::new()),
            // D8：Initiator 奇数（1 起），Responder 偶数（2 起，v2 remote forward）。
            next_ch: AtomicU32::new(if role == Role::Initiator { 1 } else { 2 }),
            alive: AtomicBool::new(true),
            peer_v2: AtomicBool::new(false),
            peer_close: AtomicBool::new(false),
            opened_total: AtomicU64::new(0),
            ctrl_tx,
            data_tx,
            open_req_tx: req_tx,
            open_req_rx: AsyncMutex::new(Some(req_rx)),
            term,
            deferred_ctrl: StdMutex::new(VecDeque::new()),
            defer_active: AtomicBool::new(false),
            handle: tokio::runtime::Handle::current(),
            epoch: Instant::now(),
            last_recv_ms: AtomicU64::new(0),
            last_send_ms: AtomicU64::new(0),
            ping_counter: AtomicU64::new(
                Instant::now().elapsed().as_nanos() as u64 ^ std::process::id() as u64,
            ),
        });

        let r_inner = inner.clone();
        let r_term = inner.term.subscribe();
        tokio::spawn(async move { reader_loop(r_inner, recv, r_term).await });

        let w_inner = inner.clone();
        let w_term = inner.term.subscribe();
        tokio::spawn(async move { writer_loop(send, ctrl_rx, w_term, w_inner).await });

        // v2 会话任务：keepalive（探测 + 周期 PING + 静默判定）与 idle reaper。
        let k_inner = inner.clone();
        let k_term = inner.term.subscribe();
        tokio::spawn(async move { keepalive_loop(k_inner, k_term).await });
        let p_inner = inner.clone();
        let p_term = inner.term.subscribe();
        tokio::spawn(async move { idle_reaper(p_inner, p_term).await });

        Self { inner }
    }

    /// 打开一条流式通道（发起方；v1 仅 Initiator，v2 起 Responder 也可——
    /// remote forward 的偶数通道，但需对端已证明 v2，否则 open_timeout 内报
    /// UnsupportedByPeer）。
    ///
    /// 流程：登记 Pending → 发 OPEN → 等 OPEN_ACK；
    /// 超时 → 回收通道并补发 CLOSE(upstream_reset)；
    /// 终态非 0 ACK → Rejected（不补发 CLOSE）；会话死亡 → SessionClosed。
    pub async fn open(&self, target: DialTarget) -> Result<MuxStream, MuxError> {
        let (ch_id, in_rx, dead) = self.open_channel(target, ChanMode::Stream).await?;
        Ok(MuxStream::new(ch_id, self.inner.clone(), in_rx, dead))
    }

    /// 打开一条数据报通道（v2 UDP 会话映射）：每个 DATA 帧携带一个 UDP 数据报。
    /// Responder 侧同样需要对端已证明 v2。
    pub async fn open_datagram(&self, target: DialTarget) -> Result<MuxDatagram, MuxError> {
        let (ch_id, in_rx, dead) = self.open_channel(target, ChanMode::Datagram).await?;
        Ok(MuxDatagram::new(ch_id, self.inner.clone(), in_rx, dead))
    }

    /// open()/open_datagram() 共用：登记 Pending → 发 OPEN/DOPEN → 等 ACK。
    /// 返回 (ch_id, 通道队列接收端, dead 标记)。
    async fn open_channel(
        &self,
        target: DialTarget,
        mode: ChanMode,
    ) -> Result<(u32, mpsc::Receiver<MuxInbound>, Arc<AtomicBool>), MuxError> {
        let inner = &self.inner;
        // 会话已死优先（spec 测试行：双端 open/accept_open 都是 SessionClosed）
        if !inner.alive.load(Ordering::SeqCst) {
            return Err(MuxError::SessionClosed);
        }
        if !target.validate() {
            return Err(MuxError::InvalidTarget(target.to_string()));
        }
        // Responder 发 OPEN = v2 线语义（偶数通道）：等对端证明（探测 PING 的
        // PONG 一个 RTT 内到达），证明不了按 UnsupportedByPeer 干净失败。
        if inner.role == Role::Responder && !inner.peer_v2.load(Ordering::SeqCst) {
            let deadline = Instant::now() + inner.cfg.open_timeout;
            while !inner.peer_v2.load(Ordering::SeqCst) {
                if !inner.alive.load(Ordering::SeqCst) {
                    return Err(MuxError::SessionClosed);
                }
                if Instant::now() >= deadline {
                    return Err(MuxError::UnsupportedByPeer(
                        "responder-side open requires a v2 peer (no PONG/WINDOW seen)",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        // 发起方侧对称的通道上限（接受方回 ACK(3)，本端直接拒绝）
        {
            let table = inner.table.lock().unwrap();
            if table.len() >= inner.cfg.max_channels {
                return Err(MuxError::Rejected {
                    status: AckStatus::CHANNEL_LIMIT,
                    detail: Some("local channel limit".into()),
                });
            }
        }
        let ch_id = inner.next_ch.fetch_add(2, Ordering::SeqCst);
        if ch_id > u32::MAX - 4 {
            // ch_id 即将耗尽：按 §1.3 优雅退出，由上层重建会话
            inner.terminate(CloseReason::SESSION_SHUTDOWN);
            return Err(MuxError::SessionClosed);
        }

        let (in_tx, in_rx) = mpsc::channel(inner.cfg.channel_queue_frames);
        let (staging_tx, staging_rx) = mpsc::unbounded_channel();
        let (ack_tx, ack_rx) = oneshot::channel();
        let dead = Arc::new(AtomicBool::new(false));
        let flow = FlowState::new();
        {
            let mut table = inner.table.lock().unwrap();
            table.insert(
                ch_id,
                Entry {
                    state: State::Pending,
                    mode,
                    in_tx: in_tx.clone(),
                    staging_tx,
                    dead: dead.clone(),
                    flow,
                    ack: Some(ack_tx),
                },
            );
        }
        inner.opened_total.fetch_add(1, Ordering::SeqCst);
        inner.spawn_channel_forwarder(ch_id, dead.clone(), staging_rx, in_tx);

        let ftype = if mode == ChanMode::Stream {
            T_OPEN
        } else {
            T_DOPEN
        };
        let frame = encode_frame(ftype, ch_id, &encode_open_payload(&target));
        if inner.ctrl_tx.send(frame).await.is_err() || !inner.alive.load(Ordering::SeqCst) {
            remove_entry(inner, ch_id, &dead, None);
            return Err(MuxError::SessionClosed);
        }

        match tokio::time::timeout(inner.cfg.open_timeout, ack_rx).await {
            Err(_) => {
                // 超时放弃：回收通道并补发 CLOSE(upstream_reset)，防对端孤儿条目（§1.3）
                remove_entry(inner, ch_id, &dead, None);
                let _ = inner.ctrl_tx.try_send(encode_frame(
                    T_CLOSE,
                    ch_id,
                    &[CloseReason::UPSTREAM_RESET],
                ));
                Err(MuxError::OpenTimeout(inner.cfg.open_timeout))
            }
            Ok(Ok(Ok(()))) => {
                if let Some(entry) = inner.table.lock().unwrap().get(&ch_id) {
                    if Arc::ptr_eq(&entry.dead, &dead) {
                        entry.flow.touch(now_ms(inner.epoch));
                    }
                }
                Ok((ch_id, in_rx, dead))
            }
            Ok(Ok(Err((status, detail)))) => Err(MuxError::Rejected { status, detail }),
            Ok(Err(_)) => {
                // oneshot 被丢弃 = 会话终止时条目被排空
                remove_entry(inner, ch_id, &dead, None);
                Err(MuxError::SessionClosed)
            }
        }
    }

    /// 等待对端 open()/open_datagram()（接受方；§2.2）。会话终止 → SessionClosed。
    /// v2 起 Initiator 侧也会收到 Responder 发起的 OPEN（remote forward）。
    pub async fn accept_open(&self) -> Result<OpenRequest, MuxError> {
        let mut term_rx = self.inner.term.subscribe();
        if term_rx.borrow_and_update().is_some() {
            return Err(MuxError::SessionClosed);
        }
        let mut slot = self.inner.open_req_rx.lock().await;
        let rx = match slot.as_mut() {
            Some(rx) => rx,
            None => return Err(MuxError::SessionClosed),
        };
        tokio::select! {
            biased;
            _ = term_rx.changed() => Err(MuxError::SessionClosed),
            req = rx.recv() => req.ok_or(MuxError::SessionClosed),
        }
    }

    /// 本端终止：发 CLOSE(3, ch 0)、关闭写半区、本端通道全部置错（§2.2，非 async、幂等）。
    pub fn shutdown(&self) {
        self.inner.terminate(CloseReason::SESSION_SHUTDOWN);
    }

    /// 会话是否仍存活。
    pub fn is_alive(&self) -> bool {
        self.inner.alive.load(Ordering::SeqCst)
    }

    /// 当前 Active 通道数与历史通道总数。
    pub fn stats(&self) -> MuxStats {
        let table = self.inner.table.lock().unwrap();
        let open = table.values().filter(|e| e.state == State::Active).count();
        MuxStats {
            channels_open: open,
            channels_total: self.inner.opened_total.load(Ordering::SeqCst),
        }
    }

    /// 会话配置（只读快照）。
    pub fn config(&self) -> &MuxConfig {
        &self.inner.cfg
    }

    /// 会话是否由对端线帧 CLOSE(ch 0) 关闭（对端主动终止，而非传输层断开）。
    /// T2 链路引导契约：CLI/FFI 监督循环据此决定"优雅退出"还是"退避重建"。
    pub fn peer_closed(&self) -> bool {
        self.inner.peer_close.load(Ordering::SeqCst)
    }

    /// 对端是否已证明 v2 能力（收到过 PING/PONG/WINDOW）。
    pub fn peer_is_v2(&self) -> bool {
        self.inner.peer_v2.load(Ordering::SeqCst)
    }

    /// 等待会话终止，返回终止原因（CloseReason）。已在终止态则立即返回。
    pub async fn wait_closed(&self) -> u8 {
        let mut rx = self.inner.term.subscribe();
        loop {
            if let Some(reason) = *rx.borrow_and_update() {
                return reason;
            }
            if rx.changed().await.is_err() {
                // term sender 随 Inner 释放：会话对象全部丢弃，按会话关闭处理。
                return CloseReason::SESSION_SHUTDOWN;
            }
        }
    }
}
