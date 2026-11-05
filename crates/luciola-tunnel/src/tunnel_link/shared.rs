use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::forward::{
    start_forward_endpoint, start_local_forward, start_remote_forward, start_udp_forward,
    ForwardAcl, ForwardEndpointGuard, ForwardRule, ForwardStatus, LocalForwardConfig,
    LocalForwardGuard, UdpForwardConfig, UdpForwardGuard,
};
use crate::mux::{DialTarget, MuxConfig, MuxSession};
use crate::TunnelError;

use super::*;

// ---------------------------------------------------------------- Shared

pub(crate) struct Shared {
    pub(crate) identity_seed: Vec<u8>,
    pub(crate) base: StdMutex<Option<TunnelBase>>,
    pub(crate) reporter: StdMutex<Option<Arc<dyn TunnelReporter>>>,
    pub(crate) port_override: AtomicU16,
    /// 隧道 mux keepalive 覆盖（interval_ms, dead_after_ms）；0 interval = 关闭。
    pub(crate) keepalive: StdMutex<(u64, u64)>,
    pub(crate) registry: StdMutex<Registry>,
    pub(crate) live: StdMutex<Live>,
    pub(crate) wake: Notify,
}

/// 停止命令的注册表/活跃表选择器（locals / udps / remotes 三张同构表共用）。
type RegTableSel<'a> = &'a dyn Fn(&mut Registry) -> &mut BTreeMap<u16, ForwardReg>;
type LiveTableSel<'a, T> = &'a dyn Fn(&Live) -> &BTreeMap<u16, (DialTarget, T)>;

impl Shared {
    pub(crate) fn snapshot(&self) -> Snap {
        let reg = self.registry.lock().unwrap();
        let base = self.base.lock().unwrap().clone();
        let port_override = self.port_override.load(Ordering::Relaxed);
        Snap {
            paused: reg.paused,
            base,
            port_override,
            locals: reg
                .locals
                .iter()
                .map(|(p, r)| (*p, r.target.clone()))
                .collect(),
            udps: reg
                .udps
                .iter()
                .map(|(p, r)| (*p, r.target.clone()))
                .collect(),
            endpoint: reg.endpoint.as_ref().map(|e| e.rules.clone()),
            remotes: reg
                .remotes
                .iter()
                .map(|(p, r)| (*p, r.target.clone()))
                .collect(),
            remote_endpoint: reg.remote_endpoint.as_ref().map(|e| e.rules.clone()),
        }
    }

    /// supervisor 用：把 keepalive 覆盖折进 MuxConfig。
    pub(crate) fn mux_config(&self) -> MuxConfig {
        let mut cfg = MuxConfig::default();
        let (interval_ms, dead_after_ms) = *self.keepalive.lock().unwrap();
        if interval_ms == 0 {
            cfg.keepalive_interval = None;
            cfg.keepalive_dead_after = None;
        } else {
            cfg.keepalive_interval = Some(Duration::from_millis(interval_ms));
            cfg.keepalive_dead_after = Some(Duration::from_millis(dead_after_ms.max(interval_ms)));
        }
        cfg
    }

    /// 无锁调用 reporter（锁内禁止上报）。
    pub(crate) fn report(&self, kind: &str, detail: String) {
        let r = self.reporter.lock().unwrap().clone();
        if let Some(r) = r {
            r.report(kind, detail);
        }
    }

    /// 通过 TunnelError 自带的 (kind, detail) 上报。
    pub(crate) fn report_err(&self, e: &TunnelError) {
        let (kind, detail) = e.to_state();
        self.report(kind, detail);
    }

    /// Dial 基址守卫（locals/udps/remote_endpoint 共用）。
    pub(crate) fn require_dial_base(
        &self,
        what: &str,
        alt: &str,
    ) -> Result<TunnelBase, TunnelError> {
        let base = self.base.lock().unwrap().clone().ok_or_else(|| {
            TunnelError::NotConfigured(format!(
                "隧道未配置：先 connect() 建立发起端会话，再注册{what}"
            ))
        })?;
        if !base.is_dial() {
            return Err(TunnelError::RoleMismatch(format!(
                "{what} 只能用于 connect()（发起端）会话；本会话是 listen()（服务端），请改用{alt}"
            )));
        }
        Ok(base)
    }

    /// Listen 基址守卫（endpoint/remotes 共用）。
    pub(crate) fn require_listen_base(
        &self,
        what: &str,
        alt: &str,
    ) -> Result<TunnelBase, TunnelError> {
        let base = self.base.lock().unwrap().clone().ok_or_else(|| {
            TunnelError::NotConfigured(format!(
                "隧道未配置：先 listen() 建立服务端会话，再启用{what}"
            ))
        })?;
        if base.is_dial() {
            return Err(TunnelError::RoleMismatch(format!(
                "{what} 只能用于 listen()（服务端）会话；本会话是 connect()（发起端），请改用{alt}"
            )));
        }
        Ok(base)
    }

    // ---- 命令处理（cmd 线程；探测用 std::net，无 runtime） ----

    pub(crate) fn cmd_start_local(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        let target = DialTarget::new(host, port);
        if !target.validate() {
            return Err(TunnelError::InvalidTarget(format!(
                "非法转发目标 {target}（端口 0 / 未指定 / 组播 / 广播地址或非法主机名均不允许）",
            )));
        }
        self.require_dial_base("本地转发", "enable_forward_endpoint")?;
        if listen_port != 0 {
            // D6 同步段探测：绑不上就立刻 false + on_state（不等 supervisor）。
            std::net::TcpListener::bind(("127.0.0.1", listen_port))
                .map_err(|e| TunnelError::Bind(format!("127.0.0.1:{listen_port}: {e}")))?;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.locals.get_mut(&listen_port) {
                // 同端口重复注册：只换目标，保留历史计数。
                Some(entry) => entry.target = target,
                None => {
                    reg.locals.insert(
                        listen_port,
                        ForwardReg {
                            target,
                            base: ForwardStatus::default(),
                        },
                    );
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_start_udp(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        let target = DialTarget::new(host, port);
        if !target.validate() {
            return Err(TunnelError::InvalidTarget(format!(
                "非法 UDP 转发目标 {target}",
            )));
        }
        self.require_dial_base("UDP 转发", "enable_forward_endpoint")?;
        if listen_port != 0 {
            std::net::UdpSocket::bind(("127.0.0.1", listen_port))
                .map_err(|e| TunnelError::Bind(format!("127.0.0.1:{listen_port} (udp): {e}")))?;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.udps.get_mut(&listen_port) {
                Some(entry) => entry.target = target,
                None => {
                    reg.udps.insert(
                        listen_port,
                        ForwardReg {
                            target,
                            base: ForwardStatus::default(),
                        },
                    );
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    /// 停止一个 TCP/UDP/remote 转发：先精确键，再回退按活链实测端口匹配
    /// （stats 展示的是实端口，stop 收到的值应与之一致）。`reg_table` 选择
    /// 注册表，`live_table` 选择对应活跃表（Guard 统一实现 [`ListenPort`]）。
    /// 锁序：registry 先于 live；本函数纯同步、不跨 await。
    pub(crate) fn cmd_stop_forward<T: ListenPort>(
        &self,
        reg_table: RegTableSel<'_>,
        live_table: LiveTableSel<'_, T>,
        what: &str,
        listen_port: u16,
    ) -> Result<(), TunnelError> {
        let removed = {
            let mut reg = self.registry.lock().unwrap();
            if reg_table(&mut reg).remove(&listen_port).is_some() {
                true
            } else {
                let hit = {
                    let live = self.live.lock().unwrap();
                    reg_table(&mut reg)
                        .keys()
                        .find(|&&k| {
                            k != listen_port
                                && live_table(&live)
                                    .get(&k)
                                    .is_some_and(|(_, g)| g.listen_port() == listen_port)
                        })
                        .copied()
                };
                hit.is_some_and(|k| reg_table(&mut reg).remove(&k).is_some())
            }
        };
        self.wake.notify_one();
        if removed {
            Ok(())
        } else {
            Err(TunnelError::Stopped(format!(
                "{what} {listen_port} 未在转发注册表中",
            )))
        }
    }

    pub(crate) fn cmd_enable_endpoint(&self, rules: Vec<ForwardRule>) -> Result<(), TunnelError> {
        let base = self.require_listen_base("转发端点", "start_local_forward")?;
        validate_rules(&rules)?;
        // tunnel_port 冲突同步探测（双栈：v4 必须干净；v6 缺失环境忽略）。
        let tp = base.tunnel_port(self.port_override.load(Ordering::Relaxed))?;
        std::net::TcpListener::bind(("0.0.0.0", tp))
            .map_err(|e| TunnelError::Bind(format!("0.0.0.0:{tp}: {e}")))?;
        if let Err(e) = std::net::TcpListener::bind(("[::]", tp)) {
            if e.kind() == ErrorKind::AddrInUse {
                return Err(TunnelError::Bind(format!("[::]:{tp}: {e}")));
            }
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.endpoint.as_mut() {
                // 重复启用：换规则、保留历史计数。
                Some(entry) => entry.rules = rules,
                None => {
                    reg.endpoint = Some(EndpointReg {
                        rules,
                        base: ForwardStatus::default(),
                    });
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_disable_endpoint(&self) -> Result<(), TunnelError> {
        self.registry.lock().unwrap().endpoint = None;
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_start_remote(
        &self,
        listen_port: u16,
        host: String,
        port: u16,
    ) -> Result<(), TunnelError> {
        let target = DialTarget::new(host, port);
        if !target.validate() {
            return Err(TunnelError::InvalidTarget(format!(
                "非法 remote forward 目标 {target}",
            )));
        }
        self.require_listen_base("remote forward", "enable_remote_endpoint")?;
        if listen_port != 0 {
            std::net::TcpListener::bind(("127.0.0.1", listen_port))
                .map_err(|e| TunnelError::Bind(format!("127.0.0.1:{listen_port}: {e}")))?;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.remotes.get_mut(&listen_port) {
                Some(entry) => entry.target = target,
                None => {
                    reg.remotes.insert(
                        listen_port,
                        ForwardReg {
                            target,
                            base: ForwardStatus::default(),
                        },
                    );
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_enable_remote_endpoint(
        &self,
        rules: Vec<ForwardRule>,
    ) -> Result<(), TunnelError> {
        self.require_dial_base("remote endpoint", "start_remote_forward")?;
        validate_rules(&rules)?;
        {
            let mut reg = self.registry.lock().unwrap();
            match reg.remote_endpoint.as_mut() {
                Some(entry) => entry.rules = rules,
                None => {
                    reg.remote_endpoint = Some(EndpointReg {
                        rules,
                        base: ForwardStatus::default(),
                    });
                }
            }
        }
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_disable_remote_endpoint(&self) -> Result<(), TunnelError> {
        self.registry.lock().unwrap().remote_endpoint = None;
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_set_tunnel_port(&self, port: u16) -> Result<(), TunnelError> {
        // 0 = 清除覆盖，恢复 secure_port + 1 推导。
        self.port_override.store(port, Ordering::Relaxed);
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn cmd_set_base(&self, base: TunnelBase, reporter: Arc<dyn TunnelReporter>) {
        *self.reporter.lock().unwrap() = Some(reporter);
        *self.base.lock().unwrap() = Some(base);
        self.registry.lock().unwrap().paused = false;
        self.wake.notify_one();
    }

    pub(crate) fn cmd_pause(&self) {
        self.registry.lock().unwrap().paused = true;
        self.wake.notify_one();
    }

    // ---- supervisor 侧 ----

    /// 挂上新链路（active）并按注册表启动全部 Guard。
    pub(crate) async fn install(&self, session: Arc<MuxSession>, tunnel_port: u16) {
        {
            let mut live = self.live.lock().unwrap();
            live.session = Some(session.clone());
            live.link_port = tunnel_port;
            live.active = true;
        }
        self.apply_guards(&session).await;
    }

    /// 注册表 → 活跃 Guard 的增量同步（仅 supervisor；锁内无 await/上报）。
    pub(crate) async fn apply_guards(&self, session: &Arc<MuxSession>) {
        // 1) 需要停的：注册表已删（Stop）与目标变更（Restart，随后重启）。
        let (stop_ports, restart_ports) = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            let mut stop = Vec::new();
            let mut restart = Vec::new();
            for (port, (target, _)) in &live.locals {
                match reg.locals.get(port) {
                    None => stop.push(*port),
                    Some(r) if r.target != *target => restart.push(*port),
                    _ => {}
                }
            }
            for (port, (target, _)) in &live.udps {
                match reg.udps.get(port) {
                    None => stop.push(*port),
                    Some(r) if r.target != *target => restart.push(*port),
                    _ => {}
                }
            }
            for (port, (target, _)) in &live.remotes {
                match reg.remotes.get(port) {
                    None => stop.push(*port),
                    Some(r) if r.target != *target => restart.push(*port),
                    _ => {}
                }
            }
            (stop, restart)
        };
        for port in stop_ports.iter().chain(restart_ports.iter()) {
            let taken = self.live.lock().unwrap().locals.remove(port);
            if let Some((_, guard)) = taken {
                guard.stop().await;
                if restart_ports.contains(port) {
                    // 目标变更：历史计数折叠进仍在的注册表条目。
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(entry) = reg.locals.get_mut(port) {
                        fold(&mut entry.base, guard.status());
                    }
                }
            }
            let taken = self.live.lock().unwrap().udps.remove(port);
            if let Some((_, guard)) = taken {
                guard.stop().await;
                if restart_ports.contains(port) {
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(entry) = reg.udps.get_mut(port) {
                        fold(&mut entry.base, guard.status());
                    }
                }
            }
            let taken = self.live.lock().unwrap().remotes.remove(port);
            if let Some((_, guard)) = taken {
                guard.stop().await;
                if restart_ports.contains(port) {
                    let mut reg = self.registry.lock().unwrap();
                    if let Some(entry) = reg.remotes.get_mut(port) {
                        fold(&mut entry.base, guard.status());
                    }
                }
            }
        }

        // 2) 需要启的：注册表有、live 没有（含刚被 Restart 停掉的）。
        let starts: Vec<(u16, DialTarget)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            reg.locals
                .iter()
                .filter(|(p, _)| !live.locals.contains_key(p))
                .map(|(p, r)| (*p, r.target.clone()))
                .collect()
        };
        for (port, target) in starts {
            match start_local_forward(
                session.clone(),
                LocalForwardConfig {
                    listen_port: port,
                    target: target.clone(),
                },
            ) {
                Ok(guard) => {
                    self.live
                        .lock()
                        .unwrap()
                        .locals
                        .insert(port, (target, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }
        let udp_starts: Vec<(u16, DialTarget)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            reg.udps
                .iter()
                .filter(|(p, _)| !live.udps.contains_key(p))
                .map(|(p, r)| (*p, r.target.clone()))
                .collect()
        };
        for (port, target) in udp_starts {
            match start_udp_forward(
                session.clone(),
                UdpForwardConfig {
                    listen_port: port,
                    target: target.clone(),
                },
            ) {
                Ok(guard) => {
                    self.live.lock().unwrap().udps.insert(port, (target, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }
        let remote_starts: Vec<(u16, DialTarget)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            reg.remotes
                .iter()
                .filter(|(p, _)| !live.remotes.contains_key(p))
                .map(|(p, r)| (*p, r.target.clone()))
                .collect()
        };
        for (port, target) in remote_starts {
            match start_remote_forward(
                session.clone(),
                LocalForwardConfig {
                    listen_port: port,
                    target: target.clone(),
                },
            ) {
                Ok(guard) => {
                    self.live
                        .lock()
                        .unwrap()
                        .remotes
                        .insert(port, (target, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }

        // 3) 两个端点（endpoint / remote_endpoint）：规则集变化则先停旧、折叠历史，再启新。
        for (want, which) in [
            (
                {
                    let reg = self.registry.lock().unwrap();
                    reg.endpoint.as_ref().map(|e| e.rules.clone())
                },
                EndpointSide::Endpoint,
            ),
            (
                {
                    let reg = self.registry.lock().unwrap();
                    reg.remote_endpoint.as_ref().map(|e| e.rules.clone())
                },
                EndpointSide::RemoteEndpoint,
            ),
        ] {
            self.sync_endpoint(session, want, which).await;
        }
    }

    /// 单个端点面（endpoint / remote_endpoint）的停旧-启新同步。
    pub(crate) async fn sync_endpoint(
        &self,
        session: &Arc<MuxSession>,
        want: Option<Vec<ForwardRule>>,
        which: EndpointSide,
    ) {
        let have = {
            let live = self.live.lock().unwrap();
            match which {
                EndpointSide::Endpoint => live.endpoint.as_ref().map(|e| e.0.clone()),
                EndpointSide::RemoteEndpoint => live.remote_endpoint.as_ref().map(|e| e.0.clone()),
            }
        };
        if want == have {
            return;
        }
        let taken = { self.live.lock().unwrap().take_for(which) };
        if let Some((old_rules, guard)) = taken {
            guard.stop().await;
            let mut reg = self.registry.lock().unwrap();
            let slot = match which {
                EndpointSide::Endpoint => reg.endpoint.as_mut(),
                EndpointSide::RemoteEndpoint => reg.remote_endpoint.as_mut(),
            };
            if let Some(entry) = slot {
                // 条目仍在（换规则场景）→ 折叠历史；已注销则自然丢弃。
                if want.is_some() || entry.rules == old_rules {
                    fold(&mut entry.base, guard.status());
                }
            }
        }
        if let Some(rules) = want {
            match start_forward_endpoint(session.clone(), ForwardAcl::new(rules.clone())) {
                Ok(guard) => {
                    self.live.lock().unwrap().set_for(which, (rules, guard));
                }
                Err(e) => self.report_err(&e),
            }
        }
    }

    /// 拆除链路与全部活跃 Guard；计数折叠回注册表（channels_open 归零不累计）。
    pub(crate) async fn teardown(&self) {
        let (locals, udps, remotes, ep, rep, session) = {
            let mut live = self.live.lock().unwrap();
            live.active = false;
            live.link_port = 0;
            let locals = std::mem::take(&mut live.locals);
            let udps = std::mem::take(&mut live.udps);
            let remotes = std::mem::take(&mut live.remotes);
            let ep = live.endpoint.take();
            let rep = live.remote_endpoint.take();
            let session = live.session.take();
            (locals, udps, remotes, ep, rep, session)
        };
        if let Some(s) = session {
            s.shutdown();
        }
        // 先停（冻结计数）再折叠。
        for (_, guard) in locals.values() {
            guard.stop().await;
        }
        for (_, guard) in udps.values() {
            guard.stop().await;
        }
        for (_, guard) in remotes.values() {
            guard.stop().await;
        }
        if let Some((_, guard)) = &ep {
            guard.stop().await;
        }
        if let Some((_, guard)) = &rep {
            guard.stop().await;
        }
        {
            let mut reg = self.registry.lock().unwrap();
            for (port, (_, guard)) in &locals {
                if let Some(entry) = reg.locals.get_mut(port) {
                    fold(&mut entry.base, guard.status());
                }
            }
            for (port, (_, guard)) in &udps {
                if let Some(entry) = reg.udps.get_mut(port) {
                    fold(&mut entry.base, guard.status());
                }
            }
            for (port, (_, guard)) in &remotes {
                if let Some(entry) = reg.remotes.get_mut(port) {
                    fold(&mut entry.base, guard.status());
                }
            }
            if let Some((_, guard)) = &ep {
                if let Some(entry) = reg.endpoint.as_mut() {
                    fold(&mut entry.base, guard.status());
                }
            }
            if let Some((_, guard)) = &rep {
                if let Some(entry) = reg.remote_endpoint.as_mut() {
                    fold(&mut entry.base, guard.status());
                }
            }
        }
    }

    /// 统计行（registry 先于 live；只读短锁；锁内不 await、不上报）。
    pub(crate) fn stats(&self) -> Vec<ForwardStat> {
        let mut rows = Vec::new();
        // 端点行（registry → live）：无注册端点时不产生行。
        let endpoint_rows: Vec<(ForwardKind, ForwardStatus, bool, u16)> = {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            let mut rows = Vec::new();
            for (kind, entry, live_guard) in [
                (
                    ForwardKind::Endpoint,
                    reg.endpoint.as_ref(),
                    live.endpoint.as_ref().map(|(_, g)| g.status()),
                ),
                (
                    ForwardKind::RemoteEndpoint,
                    reg.remote_endpoint.as_ref(),
                    live.remote_endpoint.as_ref().map(|(_, g)| g.status()),
                ),
            ] {
                let Some(entry) = entry else { continue };
                let listen = if live.link_port != 0 {
                    live.link_port
                } else {
                    let base = self.base.lock().unwrap().clone();
                    let ov = self.port_override.load(Ordering::Relaxed);
                    // 无链路：报告按基址推导的「应然」端口（行仍可见，active=false）。
                    base.as_ref()
                        .and_then(|b| b.tunnel_port(ov).ok())
                        .unwrap_or(0)
                };
                rows.push((kind, entry.base, live_guard, live.active, listen));
            }
            rows.into_iter()
                .map(|(kind, base, live_s, active, listen)| {
                    (
                        kind,
                        match live_s {
                            Some(s) => merge(&base, &s),
                            None => base,
                        },
                        active,
                        listen,
                    )
                })
                .collect()
        };
        // 本地行（registry → live）。
        {
            let reg = self.registry.lock().unwrap();
            let live = self.live.lock().unwrap();
            for (port, entry) in &reg.locals {
                match live.locals.get(port) {
                    Some((_, guard)) => {
                        let listen = if *port == 0 {
                            guard.local_addr().port()
                        } else {
                            *port
                        };
                        rows.push(ForwardStat {
                            active: live.active,
                            listen_port: listen,
                            status: merge(&entry.base, &guard.status()),
                            kind: ForwardKind::Local,
                        });
                    }
                    None => rows.push(ForwardStat {
                        active: false,
                        listen_port: *port,
                        status: entry.base,
                        kind: ForwardKind::Local,
                    }),
                }
            }
            for (port, entry) in &reg.udps {
                match live.udps.get(port) {
                    Some((_, guard)) => {
                        let listen = if *port == 0 {
                            guard.local_addr().port()
                        } else {
                            *port
                        };
                        rows.push(ForwardStat {
                            active: live.active,
                            listen_port: listen,
                            status: merge(&entry.base, &guard.status()),
                            kind: ForwardKind::UdpLocal,
                        });
                    }
                    None => rows.push(ForwardStat {
                        active: false,
                        listen_port: *port,
                        status: entry.base,
                        kind: ForwardKind::UdpLocal,
                    }),
                }
            }
            for (port, entry) in &reg.remotes {
                match live.remotes.get(port) {
                    Some((_, guard)) => {
                        let listen = if *port == 0 {
                            guard.local_addr().port()
                        } else {
                            *port
                        };
                        rows.push(ForwardStat {
                            active: live.active,
                            listen_port: listen,
                            status: merge(&entry.base, &guard.status()),
                            kind: ForwardKind::Remote,
                        });
                    }
                    None => rows.push(ForwardStat {
                        active: false,
                        listen_port: *port,
                        status: entry.base,
                        kind: ForwardKind::Remote,
                    }),
                }
            }
        }
        for (kind, status, active, listen) in endpoint_rows {
            rows.push(ForwardStat {
                active,
                listen_port: listen,
                status,
                kind,
            });
        }
        rows
    }
}

#[derive(Clone, Copy)]
pub(crate) enum EndpointSide {
    Endpoint,
    RemoteEndpoint,
}

/// Guard 统一取实际监听端口（stop 回退匹配用）。
pub trait ListenPort {
    /// The port the guard actually bound (system-assigned when 0 was requested).
    fn listen_port(&self) -> u16;
}

impl ListenPort for LocalForwardGuard {
    fn listen_port(&self) -> u16 {
        self.local_addr().port()
    }
}

impl ListenPort for UdpForwardGuard {
    fn listen_port(&self) -> u16 {
        self.local_addr().port()
    }
}

impl Live {
    pub(crate) fn take_for(
        &mut self,
        which: EndpointSide,
    ) -> Option<(Vec<ForwardRule>, ForwardEndpointGuard)> {
        match which {
            EndpointSide::Endpoint => self.endpoint.take(),
            EndpointSide::RemoteEndpoint => self.remote_endpoint.take(),
        }
    }

    pub(crate) fn set_for(
        &mut self,
        which: EndpointSide,
        v: (Vec<ForwardRule>, ForwardEndpointGuard),
    ) {
        match which {
            EndpointSide::Endpoint => self.endpoint = Some(v),
            EndpointSide::RemoteEndpoint => self.remote_endpoint = Some(v),
        }
    }
}

/// 端点/转发规则公共校验：非空 + 起止端口正序。
pub(crate) fn validate_rules(rules: &[ForwardRule]) -> Result<(), TunnelError> {
    if rules.is_empty() {
        return Err(TunnelError::InvalidRule(
            "转发端点规则表为空：至少放行一条 (host, port_from..=port_to)".into(),
        ));
    }
    for r in rules {
        if r.port_from > r.port_to {
            return Err(TunnelError::InvalidRule(format!(
                "规则 {}:{}-{} 起止端口倒置",
                r.host, r.port_from, r.port_to
            )));
        }
    }
    Ok(())
}

/// 活计数叠加进历史基数（channels_open 不累计：拆除即归零）。
pub(crate) fn fold(base: &mut ForwardStatus, live: ForwardStatus) {
    base.channels_total = base.channels_total.saturating_add(live.channels_total);
    base.channels_open = 0;
    base.dial_denied = base.dial_denied.saturating_add(live.dial_denied);
    base.dial_failed = base.dial_failed.saturating_add(live.dial_failed);
}

/// 历史基数 + 活计数（读侧行）。
pub(crate) fn merge(base: &ForwardStatus, live: &ForwardStatus) -> ForwardStatus {
    ForwardStatus {
        channels_open: base.channels_open.saturating_add(live.channels_open),
        channels_total: base.channels_total.saturating_add(live.channels_total),
        dial_denied: base.dial_denied.saturating_add(live.dial_denied),
        dial_failed: base.dial_failed.saturating_add(live.dial_failed),
    }
}
