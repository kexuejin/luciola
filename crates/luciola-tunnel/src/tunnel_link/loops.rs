use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;
use tracing::debug;

use crate::mux::{MuxSession, Role};

use super::*;

// ---------------------------------------------------------------- 无活等待

/// 空转等待：true = 被唤醒（重新快照），false = 关停。
pub(crate) async fn idle_wait(
    shared: &Shared,
    stop: &mut tokio_mpsc::UnboundedReceiver<()>,
) -> bool {
    tokio::select! {
        _ = stop.recv() => false,
        _ = shared.wake.notified() => true,
    }
}

// ---------------------------------------------------------------- 建立隧道

/// 拨号 / 监听 + 握手，带指数退避重试；每个阻塞点都可被关停/重配打断。
/// 成功重置退避；建立期失败上报 kind="retrying"（前缀 tunnel_link_failed /
/// tunnel_bind_failed / tunnel_handshake_failed）。
pub(crate) async fn establish(
    shared: &Shared,
    base: &TunnelBase,
    tunnel_port: u16,
    stop: &mut tokio_mpsc::UnboundedReceiver<()>,
    backoff: &mut Duration,
) -> EstablishOutcome {
    match base {
        TunnelBase::Dial {
            addresses,
            pinned_peer_public_key,
            ..
        } => loop {
            let attempt = tokio::select! {
                r = tokio::time::timeout(
                    Duration::from_secs(10),
                    luciola::link::secure::connect_secure_raced(
                        addresses.clone(),
                        tunnel_port,
                        &shared.identity_seed,
                        pinned_peer_public_key,
                    ),
                ) => r,
                _ = stop.recv() => return EstablishOutcome::Shutdown,
                _ = shared.wake.notified() => return EstablishOutcome::Restart,
            };
            match attempt {
                Ok(Ok(s)) => {
                    *backoff = BACKOFF_INIT;
                    return EstablishOutcome::Stream(Box::new(s));
                }
                Ok(Err(e)) => {
                    shared.report(
                        "retrying",
                        format!("tunnel_link_failed: {e}; next attempt in {backoff:?}",),
                    );
                }
                Err(_) => {
                    shared.report(
                        "retrying",
                        format!(
                            "tunnel_link_failed: dial timed out (10s); next attempt in {backoff:?}",
                        ),
                    );
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(*backoff) => {}
                _ = stop.recv() => return EstablishOutcome::Shutdown,
                _ = shared.wake.notified() => return EstablishOutcome::Restart,
            }
            *backoff = (*backoff * 2).min(BACKOFF_MAX);
        },
        TunnelBase::Listen { expected_peer, .. } => {
            let listener = tokio::select! {
                r = luciola::link::bind_dual_stack_listener(tunnel_port) => match r {
                    Ok(l) => l,
                    Err(e) => {
                        shared.report(
                            "retrying",
                            format!(
                                "tunnel_bind_failed: {e}; next attempt in {backoff:?}",
                            ),
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(*backoff) => {}
                            _ = stop.recv() => return EstablishOutcome::Shutdown,
                            _ = shared.wake.notified() => return EstablishOutcome::Restart,
                        }
                        *backoff = (*backoff * 2).min(BACKOFF_MAX);
                        return EstablishOutcome::Restart;
                    }
                },
                _ = stop.recv() => return EstablishOutcome::Shutdown,
                // 重配（含 set_tunnel_port）→ listener 随作用域释放，外层重绑。
                _ = shared.wake.notified() => return EstablishOutcome::Restart,
            };
            loop {
                let attempt = tokio::select! {
                    r = luciola::link::secure::accept_secure(
                        &listener,
                        &shared.identity_seed,
                        expected_peer.as_deref(),
                    ) => r,
                    _ = stop.recv() => return EstablishOutcome::Shutdown,
                    _ = shared.wake.notified() => return EstablishOutcome::Restart,
                };
                match attempt {
                    Ok(s) => {
                        *backoff = BACKOFF_INIT;
                        return EstablishOutcome::Stream(Box::new(s));
                    }
                    Err(e) => {
                        // 握手失败不杀监听器（镜像消息链路）；短退避防畸形对端忙循环。
                        shared.report(
                            "retrying",
                            format!("tunnel_handshake_failed: {e}; next accept in {backoff:?}",),
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(*backoff) => {}
                            _ = stop.recv() => return EstablishOutcome::Shutdown,
                            _ = shared.wake.notified() => return EstablishOutcome::Restart,
                        }
                        *backoff = (*backoff * 2).min(BACKOFF_MAX);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- 主监督循环

pub(crate) async fn supervisor(shared: Arc<Shared>, mut stop: tokio_mpsc::UnboundedReceiver<()>) {
    let mut backoff = BACKOFF_INIT;
    loop {
        let snap = shared.snapshot();
        // 1) 无活可干（pause / 全部注销）：拆除后空转等待。
        if snap.paused || !snap.has_work() {
            shared.teardown().await;
            if !idle_wait(&shared, &mut stop).await {
                return;
            }
            continue;
        }
        // 2) 基址未注入：控制面同步段已用 NotConfigured 拒绝过；等 set_base。
        let base = match snap.base.clone() {
            Some(b) => b,
            None => {
                if !idle_wait(&shared, &mut stop).await {
                    return;
                }
                continue;
            }
        };
        let tunnel_port = match base.tunnel_port(snap.port_override) {
            Ok(p) => p,
            Err(e) => {
                shared.report_err(&e);
                if !idle_wait(&shared, &mut stop).await {
                    return;
                }
                continue;
            }
        };
        // 3) 建立隧道（懒：走到这里才有网络动作）。
        let stream = match establish(&shared, &base, tunnel_port, &mut stop, &mut backoff).await {
            EstablishOutcome::Stream(s) => *s,
            EstablishOutcome::Restart => continue,
            EstablishOutcome::Shutdown => return,
        };
        let role = if base.is_dial() {
            Role::Initiator
        } else {
            Role::Responder
        };
        let session = Arc::new(MuxSession::start(stream, role, shared.mux_config()));
        debug!(port = tunnel_port, "tunnel link established");
        shared.install(session.clone(), tunnel_port).await;

        // 4) 运行期：链路死亡 / 关停 / 配置变更。
        loop {
            tokio::select! {
                _ = session.wait_closed() => break,
                _ = stop.recv() => {
                    shared.teardown().await;
                    return;
                }
                _ = shared.wake.notified() => {
                    let now = shared.snapshot();
                    let now_port = now.base
                        .as_ref()
                        .and_then(|b| b.tunnel_port(now.port_override).ok());
                    let changed = now.paused
                        || !now.has_work()
                        || now.base.as_ref() != Some(&base)
                        || now_port != Some(tunnel_port);
                    if changed {
                        // pause / 改基址 / 改 tunnel_port / 全部注销 → 统一拆除重建。
                        break;
                    }
                    // 仅注册表增量（新增/换目标）→ 原链路上热更新。
                    shared.apply_guards(&session).await;
                }
            }
        }
        // 5) 链路死亡或配置变化：拆除（计数折叠）→ 退避 → 外层重建。
        shared.teardown().await;
        debug!("tunnel link torn down; backing off before rebuild");
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = stop.recv() => return,
            _ = shared.wake.notified() => {}
        }
    }
}

// ---------------------------------------------------------------- 命令线程

/// 执行一条命令并应答；返回 false = 停机。
pub(crate) fn handle_cmd(cmd: Cmd, shared: &Shared) -> bool {
    match cmd {
        Cmd::StartLocal {
            listen_port,
            host,
            port,
            reply,
        } => {
            let _ = reply.send(shared.cmd_start_local(listen_port, host, port));
            true
        }
        Cmd::StopLocal { listen_port, reply } => {
            let _ = reply.send(shared.cmd_stop_forward(
                &|reg| &mut reg.locals,
                &|live| &live.locals,
                "listen_port",
                listen_port,
            ));
            true
        }
        Cmd::StartUdp {
            listen_port,
            host,
            port,
            reply,
        } => {
            let _ = reply.send(shared.cmd_start_udp(listen_port, host, port));
            true
        }
        Cmd::StopUdp { listen_port, reply } => {
            let _ = reply.send(shared.cmd_stop_forward(
                &|reg| &mut reg.udps,
                &|live| &live.udps,
                "udp listen_port",
                listen_port,
            ));
            true
        }
        Cmd::EnableEndpoint { rules, reply } => {
            let _ = reply.send(shared.cmd_enable_endpoint(rules));
            true
        }
        Cmd::DisableEndpoint { reply } => {
            let _ = reply.send(shared.cmd_disable_endpoint());
            true
        }
        Cmd::StartRemote {
            listen_port,
            host,
            port,
            reply,
        } => {
            let _ = reply.send(shared.cmd_start_remote(listen_port, host, port));
            true
        }
        Cmd::StopRemote { listen_port, reply } => {
            let _ = reply.send(shared.cmd_stop_forward(
                &|reg| &mut reg.remotes,
                &|live| &live.remotes,
                "remote listen_port",
                listen_port,
            ));
            true
        }
        Cmd::EnableRemoteEndpoint { rules, reply } => {
            let _ = reply.send(shared.cmd_enable_remote_endpoint(rules));
            true
        }
        Cmd::DisableRemoteEndpoint { reply } => {
            let _ = reply.send(shared.cmd_disable_remote_endpoint());
            true
        }
        Cmd::SetTunnelPort { port, reply } => {
            let _ = reply.send(shared.cmd_set_tunnel_port(port));
            true
        }
        Cmd::SetKeepalive {
            interval_ms,
            dead_after_ms,
        } => {
            *shared.keepalive.lock().unwrap() = (interval_ms, dead_after_ms.max(interval_ms));
            true
        }
        Cmd::SetBase { base, reporter } => {
            shared.cmd_set_base(base, reporter);
            true
        }
        Cmd::Pause => {
            shared.cmd_pause();
            true
        }
        Cmd::Shutdown => false,
    }
}

pub(crate) fn cmd_loop(
    rx: std_mpsc::Receiver<Cmd>,
    shared: Arc<Shared>,
    stop: tokio_mpsc::UnboundedSender<()>,
) {
    while let Ok(cmd) = rx.recv() {
        if !handle_cmd(cmd, &shared) {
            break;
        }
    }
    // Shutdown 或发送端全部关闭（Drop）→ 通知 supervisor 退出。
    let _ = stop.send(());
}

pub(crate) fn supervisor_thread(shared: Arc<Shared>, stop: tokio_mpsc::UnboundedReceiver<()>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("luciola-tunnel supervisor runtime 构建失败");
    rt.block_on(supervisor(shared, stop));
}
