use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use luciola::link::secure::{SecureRecvHalf, SecureSendHalf};
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use super::*;

// ---------------------------------------------------------------- 读任务

pub(crate) async fn reader_loop(
    inner: Arc<Inner>,
    mut recv: SecureRecvHalf,
    mut term_rx: watch::Receiver<Option<u8>>,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(HEADER_LEN + MAX_DATA_FRAME);
    loop {
        if term_rx.borrow_and_update().is_some() {
            break;
        }
        tokio::select! {
            biased;
            _ = term_rx.changed() => break,
            res = recv.recv(&mut buf) => match res {
                Ok(()) => {
                    inner.last_recv_ms.store(now_ms(inner.epoch), Ordering::SeqCst);
                    match decode_frame(&buf) {
                        Ok(frame) => match handle_frame(&inner, frame).await {
                            Ok(()) => {}
                            Err(()) => {
                                warn!("mux structural violation — terminating session (D9)");
                                inner.terminate(CloseReason::PROTOCOL_VIOLATION);
                                break;
                            }
                        },
                        Err(e) => {
                            warn!("mux frame decode failed: {e} — terminating session (D9)");
                            inner.terminate(CloseReason::PROTOCOL_VIOLATION);
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("mux secure recv ended: {e}");
                    inner.terminate(CloseReason::SESSION_SHUTDOWN);
                    break;
                }
            },
        }
    }
}

/// 分发一帧。Err(()) = 结构性违规，调用方按 D9 终止会话。
pub(crate) async fn handle_frame(inner: &Arc<Inner>, frame: Frame) -> Result<(), ()> {
    match frame {
        Frame::Ping { nonce } => {
            // v2 能力证明 + keepalive 应答（v1 对端不会发 PING，也不会回 PONG）
            inner.set_peer_v2();
            send_ctrl(inner, encode_frame(T_PONG, 0, &nonce.to_be_bytes()));
            Ok(())
        }
        Frame::Pong { .. } => {
            inner.set_peer_v2();
            Ok(())
        }
        Frame::Window { ch_id, delta } => {
            inner.set_peer_v2();
            if ch_id == 0 {
                return Ok(()); // 会话级 WINDOW：v2 未用，忽略
            }
            let flow = {
                let table = inner.table.lock().unwrap();
                table.get(&ch_id).map(|e| e.flow.clone())
            };
            if let Some(flow) = flow {
                apply_credit(&flow, delta);
            }
            Ok(())
        }

        Frame::Open { ch_id, host, port } => handle_open(inner, ch_id, host, port, false).await,
        Frame::DOpen { ch_id, host, port } => handle_open(inner, ch_id, host, port, true).await,

        Frame::Ack {
            ch_id,
            status,
            detail,
        } => {
            // ACK 只发给通道的发起方：Initiator 收奇数通道的 ACK；
            // Responder 收偶数通道的 ACK（v2 remote forward，需对端证明 v2）。
            let my_parity = match inner.role {
                Role::Initiator => 1,
                Role::Responder => 0,
            };
            if ch_id % 2 != my_parity {
                return Err(());
            }
            if inner.role == Role::Responder && !inner.peer_v2.load(Ordering::SeqCst) {
                return Err(());
            }
            let settled = {
                let mut table = inner.table.lock().unwrap();
                match table.get_mut(&ch_id) {
                    Some(entry) if entry.state == State::Pending && entry.ack.is_some() => {
                        let ack = entry.ack.take().unwrap();
                        if status == AckStatus::OK {
                            entry.state = State::Active;
                            Some((ack, Ok(())))
                        } else {
                            table.remove(&ch_id);
                            Some((ack, Err((status, detail))))
                        }
                    }
                    _ => None, // 未知/重复 ACK：丢弃
                }
            };
            if let Some((ack, result)) = settled {
                let _ = ack.send(result);
            }
            Ok(())
        }

        Frame::Data { ch_id, bytes } => {
            if ch_id == 0 {
                return Err(());
            }
            // 未证明 v2 的对端维持 v1 奇偶规则；证明后偶数通道（remote forward）合法。
            if !inner.peer_v2.load(Ordering::SeqCst) && ch_id % 2 == 0 {
                return Err(());
            }
            if bytes.is_empty() {
                return Ok(());
            }
            deliver_dispatch(inner, ch_id, MuxInbound::Data(bytes)).await
        }

        Frame::Eof { ch_id } => {
            if ch_id == 0 {
                return Err(());
            }
            if !inner.peer_v2.load(Ordering::SeqCst) && ch_id % 2 == 0 {
                return Err(());
            }
            deliver_dispatch(inner, ch_id, MuxInbound::Eof).await
        }

        Frame::Close { ch_id, reason } => {
            if ch_id == 0 {
                // 会话级 CLOSE（优雅退出 / 对端违规终止）：本端同步终止。
                // 标记"对端经线帧主动关闭"：与传输层 FIN（reader 直接 terminate）区分。
                inner.peer_close.store(true, Ordering::SeqCst);
                inner.terminate(reason);
                return Ok(());
            }
            if !inner.peer_v2.load(Ordering::SeqCst) && ch_id % 2 == 0 {
                return Err(());
            }
            let dead = {
                let table = inner.table.lock().unwrap();
                table.get(&ch_id).map(|e| e.dead.clone())
            };
            if let Some(dead) = dead {
                remove_entry(inner, ch_id, &dead, Some(MuxInbound::Close(reason)));
            }
            Ok(())
        }
    }
}

/// OPEN/DOPEN 共用处理。奇偶规则（D8/D9）：
/// - Responder 收到的 OPEN 必为奇数（v1 语义，始终如此）；
/// - Initiator 收到的 OPEN 必为偶数，且仅当对端已证明 v2（否则结构违规——
///   v1 对端从不发偶数 OPEN，混版时按违规终止与 v1 行为一致）。
pub(crate) async fn handle_open(
    inner: &Arc<Inner>,
    ch_id: u32,
    host: String,
    port: u16,
    datagram: bool,
) -> Result<(), ()> {
    let foreign_parity = match inner.role {
        Role::Responder => 1,
        Role::Initiator => 0,
    };
    if ch_id % 2 != foreign_parity {
        return Err(());
    }
    if inner.role == Role::Initiator && !inner.peer_v2.load(Ordering::SeqCst) {
        return Err(());
    }
    if ch_id == 0 {
        return Err(());
    }
    // 目标不合法 → 通道级 OPEN_ACK(4)，不入表、不杀会话（§1.2）。
    let target = match parse_open_target(&host, port) {
        Some(t) => t,
        None => {
            let payload = encode_ack_payload(AckStatus::BAD_TARGET, Some("invalid target"));
            send_ctrl(inner, encode_frame(T_ACK, ch_id, &payload));
            return Ok(());
        }
    };
    let (in_tx, in_rx) = mpsc::channel(inner.cfg.channel_queue_frames);
    let (staging_tx, staging_rx) = mpsc::unbounded_channel();
    let dead = Arc::new(AtomicBool::new(false));
    let flow = FlowState::new();
    // 锁内只做准入决策（无 await），事件全部在锁外发送；
    // 队列容量 ≥ max_channels，正常路径下表长永远够。
    #[derive(Clone, Copy, PartialEq)]
    enum Admit {
        Pass,
        Limit,
        Dup,
    }
    let admit = {
        use std::collections::hash_map::Entry as MapEntry;
        let mut table = inner.table.lock().unwrap();
        if table.len() >= inner.cfg.max_channels {
            Admit::Limit
        } else {
            match table.entry(ch_id) {
                MapEntry::Occupied(_) => Admit::Dup,
                MapEntry::Vacant(v) => {
                    v.insert(Entry {
                        state: State::Pending,
                        mode: if datagram {
                            ChanMode::Datagram
                        } else {
                            ChanMode::Stream
                        },
                        in_tx: in_tx.clone(),
                        staging_tx,
                        dead: dead.clone(),
                        flow,
                        ack: None,
                    });
                    Admit::Pass
                }
            }
        }
    };
    match admit {
        Admit::Limit => {
            send_ctrl(
                inner,
                encode_frame(T_ACK, ch_id, &[AckStatus::CHANNEL_LIMIT]),
            );
            return Ok(());
        }
        Admit::Dup => {
            // 重复 ch_id：不复用旧通道，回 OPEN_ACK(4)（§1.2 bad_target）
            let payload = encode_ack_payload(AckStatus::BAD_TARGET, Some("duplicate channel id"));
            send_ctrl(inner, encode_frame(T_ACK, ch_id, &payload));
            return Ok(());
        }
        Admit::Pass => {}
    }
    inner.opened_total.fetch_add(1, Ordering::SeqCst);
    inner.spawn_channel_forwarder(ch_id, dead.clone(), staging_rx, in_tx);
    let req = OpenRequest {
        target,
        ch_id,
        datagram,
        rx: Some(in_rx),
        inner: inner.clone(),
        answered: false,
    };
    if inner.open_req_tx.try_send(req).is_err() {
        // 不应发生（队列容量 ≥ max_channels）；兜底按 channel_limit 终态回收。
        remove_entry(inner, ch_id, &dead, None);
        send_ctrl(
            inner,
            encode_frame(T_ACK, ch_id, &[AckStatus::CHANNEL_LIMIT]),
        );
    }
    Ok(())
}

/// 通道级数据/Eof 分发：Active 投递、Pending 即违规（OPEN_ACK 前发数据）、
/// 未知通道丢弃且只回 CLOSE(0)（D9，不杀会话）。
pub(crate) async fn deliver_dispatch(
    inner: &Arc<Inner>,
    ch_id: u32,
    msg: MuxInbound,
) -> Result<(), ()> {
    enum Target {
        Channel(
            mpsc::UnboundedSender<MuxInbound>,
            Arc<AtomicBool>,
            Arc<FlowState>,
        ),
        Pending,
        Unknown,
    }
    let target = {
        let table = inner.table.lock().unwrap();
        match table.get(&ch_id) {
            Some(entry) => match entry.state {
                State::Active => Target::Channel(
                    entry.staging_tx.clone(),
                    entry.dead.clone(),
                    entry.flow.clone(),
                ),
                State::Pending => Target::Pending,
            },
            None => Target::Unknown,
        }
    };
    match target {
        Target::Pending => Err(()), // OPEN_ACK 前收到通道帧 → 结构性违规（§1.3/D9）
        Target::Unknown => {
            if matches!(msg, MuxInbound::Data(_)) {
                let _ =
                    inner
                        .ctrl_tx
                        .try_send(encode_frame(T_CLOSE, ch_id, &[CloseReason::NORMAL]));
            }
            Ok(())
        }
        Target::Channel(staging_tx, dead, flow) => {
            deliver(inner, ch_id, dead, flow, &staging_tx, msg);
            Ok(())
        }
    }
}

/// 投递一条入站消息：只入本通道的暂存队列，**绝不在共享 read 任务里 await
/// 单通道队列**。
///
/// 旧实现直接 `in_tx.send(msg).await`：一条通道的消费端停读（黑洞上游、慢应用、
/// 没人读的 UDP 映射）填满它自己的有界队列后，read 任务就卡在那里，同会话其他
/// 通道的 OPEN/ACK/DATA 全被串行化——open() 因此假超时（Windows 默认 socket
/// 缓冲比 macOS/Linux 小，实测一条 200KB 的停顿通道能堵 read 任务 1.0–1.3s）。
/// 现在有界队列与 stall 判定都发生在该通道自己的转发任务里（[channel_forwarder]）。
///
/// 内存上限：暂存队列无界，但 Data 字节按 `Inner::inbound_budget` 入账，超出即
/// 按 §1.4 兜底只拆该通道（v2 诚实对端受窗口约束，永不触发）。
pub(crate) fn deliver(
    inner: &Arc<Inner>,
    ch_id: u32,
    dead: Arc<AtomicBool>,
    flow: Arc<FlowState>,
    staging_tx: &mpsc::UnboundedSender<MuxInbound>,
    msg: MuxInbound,
) {
    // 入站流量即通道活动（UDP 映射语义：任一方向有包就续期）。
    flow.touch(now_ms(inner.epoch));
    if let MuxInbound::Data(bytes) = &msg {
        let queued = flow.queued_in.load(Ordering::SeqCst);
        let budget = inner.inbound_budget();
        if queued.saturating_add(bytes.len()) > budget {
            warn!(
                "mux channel {ch_id} inbound {queued}+{} bytes over budget {budget} — tearing down channel only (§1.4)",
                bytes.len()
            );
            cut_channel(inner, ch_id, &dead, CloseReason::UPSTREAM_RESET);
            return;
        }
        flow.queued_in.fetch_add(bytes.len(), Ordering::SeqCst);
    }
    // 转发任务已退出（条目已回收）时丢弃：通道级终态已由别处补发。
    let _ = staging_tx.send(msg);
}

/// 只拆一条通道：回收条目 + CLOSE(reason)。会话与其余通道继续流动（§1.4）。
pub(crate) fn cut_channel(inner: &Inner, ch_id: u32, dead: &Arc<AtomicBool>, reason: u8) {
    remove_entry(inner, ch_id, dead, None);
    let _ = inner
        .ctrl_tx
        .try_send(encode_frame(T_CLOSE, ch_id, &[reason]));
}

/// 单通道站内转发任务：把暂存队列的消息按序送进本通道的有界帧队列。
///
/// §1.4 的 stall 判定点在这里：有界队列打满超过 `stall_hard_timeout` 只拆本条
/// 通道（CLOSE(2)），会话与其余通道继续流动。会话终止时经 watch 立即退出，
/// 不会一直等到 stall 超时。
pub(crate) async fn channel_forwarder(
    inner: Arc<Inner>,
    ch_id: u32,
    dead: Arc<AtomicBool>,
    mut staging: mpsc::UnboundedReceiver<MuxInbound>,
    in_tx: mpsc::Sender<MuxInbound>,
    mut term_rx: watch::Receiver<Option<u8>>,
) {
    loop {
        let msg = tokio::select! {
            biased;
            _ = term_rx.changed() => return,
            msg = staging.recv() => match msg {
                Some(msg) => msg,
                None => return, // 条目已回收 / 应用端已丢弃
            },
        };
        match tokio::time::timeout(inner.cfg.stall_hard_timeout, in_tx.send(msg)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                // 应用端已丢弃通道（Drop 已补发 CLOSE(0)）：回收本端条目
                remove_entry(&inner, ch_id, &dead, None);
                return;
            }
            Err(_) => {
                warn!(
                    "mux channel {ch_id} stalled > {:?} — tearing down channel only (§1.4)",
                    inner.cfg.stall_hard_timeout
                );
                cut_channel(&inner, ch_id, &dead, CloseReason::UPSTREAM_RESET);
                return;
            }
        }
    }
}

/// 应用对端 WINDOW credit：outstanding 递减并唤醒挂起的写方。
pub(crate) fn apply_credit(flow: &Arc<FlowState>, delta: u32) {
    let waker = {
        let mut s = flow.send.lock().unwrap();
        s.outstanding = s.outstanding.saturating_sub(delta as u64);
        s.waker.take()
    };
    if let Some(w) = waker {
        w.wake();
    }
    flow.wake.notify_one();
}

/// 消费侧 credit 上报：累计到阈值即回 WINDOW 帧（可靠路径：try_send 失败转延迟补发）。
pub(crate) fn send_credit(inner: &Arc<Inner>, ch_id: u32, flow: &Arc<FlowState>, n: usize) {
    if n == 0 {
        return;
    }
    let threshold = (inner.cfg.window_size / 2).max(1) as u64;
    let prev = flow.unacked.fetch_add(n as u64, Ordering::SeqCst) + n as u64;
    if prev < threshold {
        return;
    }
    // 单消费者通道：swap(0) 抢占清零，不会与并发消费竞争。
    let total = flow.unacked.swap(0, Ordering::SeqCst);
    if total == 0 {
        return;
    }
    let delta = total.min(u32::MAX as u64) as u32;
    let frame = encode_frame(T_WINDOW, ch_id, &delta.to_be_bytes());
    if inner.ctrl_tx.try_send(frame.clone()).is_err() {
        // credit 不可丢：丢了对端窗口永不回笼（永久卡死）。
        inner.defer_ctrl(frame);
    }
}

/// 控制帧发送（PONG 应答 / OPEN ACK）：队列满时转 `defer_ctrl` 延迟补发，
/// 绝不在共享 read 任务内 await —— 旧实现的 `send().await` 在单一 FIFO 满
/// 时会背压 reader_loop，卡住所有通道的 OPEN/ACK/DATA 处理。PONG/ACK 与
/// WINDOW/EOF/CLOSE 同为不可丢帧，走同一条 defer 路径；defer 乱序对这两类
/// 帧无害（keepalive 与"先到 DATA 后到 ACK 进 staging"均不依赖严格 FIFO）。
pub(crate) fn send_ctrl(inner: &Arc<Inner>, frame: Vec<u8>) {
    match inner.ctrl_tx.try_send(frame) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(f)) => inner.defer_ctrl(f),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!("control queue closed (writer exited)");
        }
    }
}

// ---------------------------------------------------------------- 写任务

pub(crate) async fn writer_loop(
    mut send: SecureSendHalf,
    mut frame_rx: mpsc::Receiver<Vec<u8>>,
    mut term_rx: watch::Receiver<Option<u8>>,
    inner: Arc<Inner>,
) {
    loop {
        tokio::select! {
            biased;
            // 终止优先（先发终止原因帧再 shutdown）；其余帧严格 FIFO 出队
            res = term_rx.changed() => {
                if res.is_ok() {
                    // Ref<'_> 非 Send：先拷出原因再 await 写帧
                    let reason = *term_rx.borrow_and_update();
                    if let Some(reason) = reason {
                        let _ = send.send(&encode_frame(T_CLOSE, 0, &[reason])).await;
                    }
                }
                let _ = send.shutdown().await;
                break;
            }
            frame = frame_rx.recv() => match frame {
                Some(bytes) => {
                    if send.send(&bytes).await.is_err() {
                        break;
                    }
                    inner.last_send_ms.store(now_ms(inner.epoch), Ordering::SeqCst);
                }
                None => break,
            },
        }
    }
}

// ---------------------------------------------------------------- v2 会话任务

/// keepalive（v2）：启动即发探测 PING；此后周期性在链路静默时发 PING。
/// 静默判定（dead_after）只对已证明 v2 的对端执行——v1 对端不回 PONG，
/// 永不因此被误杀（R7）。
pub(crate) async fn keepalive_loop(inner: Arc<Inner>, mut term_rx: watch::Receiver<Option<u8>>) {
    let interval = match inner.cfg.keepalive_interval {
        Some(d) if !d.is_zero() => d,
        _ => return,
    };
    let dead_after = inner.cfg.keepalive_dead_after;
    send_ping(&inner);
    loop {
        tokio::select! {
            _ = term_rx.changed() => break,
            _ = tokio::time::sleep(interval) => {}
        }
        if term_rx.borrow_and_update().is_some() {
            break;
        }
        if let Some(da) = dead_after {
            if inner.peer_v2.load(Ordering::SeqCst) {
                let last = inner.last_recv_ms.load(Ordering::SeqCst);
                if now_ms(inner.epoch).saturating_sub(last) > da.as_millis() as u64 {
                    debug!("tunnel keepalive: v2 peer silent > {da:?} — terminating session");
                    inner.terminate(CloseReason::SESSION_SHUTDOWN);
                    break;
                }
            }
        }
        let last = inner.last_send_ms.load(Ordering::SeqCst);
        if now_ms(inner.epoch).saturating_sub(last) >= interval.as_millis() as u64 {
            send_ping(&inner);
        }
    }
}

pub(crate) fn send_ping(inner: &Inner) {
    let nonce = inner.ping_counter.fetch_add(1, Ordering::SeqCst);
    let _ = inner
        .ctrl_tx
        .try_send(encode_frame(T_PING, 0, &nonce.to_be_bytes()));
}

/// 通道空闲回收（v2）：按模式检查 last_active，超时只拆该通道（CLOSE(0)，
/// 对端读端表现为 EOF），会话与其余通道继续。Pending 通道由 open_timeout 管理，
/// 不参与回收。无任何回收配置时本任务直接退出。
pub(crate) async fn idle_reaper(inner: Arc<Inner>, mut term_rx: watch::Receiver<Option<u8>>) {
    let tick = match (inner.cfg.idle_timeout, inner.cfg.udp_idle_timeout) {
        (None, None) => return,
        (a, b) => {
            let min = [a, b].into_iter().flatten().min().unwrap();
            (min / 4).max(Duration::from_millis(100))
        }
    };
    loop {
        tokio::select! {
            _ = term_rx.changed() => break,
            _ = tokio::time::sleep(tick) => {}
        }
        if term_rx.borrow_and_update().is_some() {
            break;
        }
        let now = now_ms(inner.epoch);
        let victims: Vec<(u32, Arc<AtomicBool>, Arc<FlowState>)> = {
            let table = inner.table.lock().unwrap();
            table
                .iter()
                .filter(|(_, e)| e.state == State::Active)
                .filter(|(_, e)| {
                    let limit = match e.mode {
                        ChanMode::Stream => inner.cfg.idle_timeout,
                        ChanMode::Datagram => inner.cfg.udp_idle_timeout,
                    };
                    match limit {
                        Some(d) => {
                            now.saturating_sub(e.flow.last_active_ms.load(Ordering::Relaxed))
                                > d.as_millis() as u64
                        }
                        None => false,
                    }
                })
                .map(|(ch, e)| (*ch, e.dead.clone(), e.flow.clone()))
                .collect()
        };
        for (ch_id, dead, _flow) in victims {
            debug!("mux channel {ch_id} idle — recycling (CLOSE normal)");
            remove_entry(
                &inner,
                ch_id,
                &dead,
                Some(MuxInbound::Close(CloseReason::NORMAL)),
            );
            let _ = inner
                .ctrl_tx
                .try_send(encode_frame(T_CLOSE, ch_id, &[CloseReason::NORMAL]));
        }
    }
}
