//! 隧道链路控制面。
//!
//! `TunnelLink` 是**独立于消息链路**的第二套监督实例：两条专用 OS 线程
//! （命令线程 + supervisor 运行时线程）持有自己的 TCP 连接与 `MuxSession`，
//! 数据面（转发字节流）永不跨 FFI —— 逐帧回调在高吞吐下不可用，FFI 只暴露
//! 控制面。uniffi / node 两个绑定层复用本模块，各自的事件回调只需实现
//! `TunnelReporter` 做一层适配。
//!
//! ## 线程模型（回调重入防死锁）
//!
//! - **cmd 线程**（`luciola-tunnel-cmd`）：`std::sync::mpsc` 无界通道接收
//!   FFI 控制命令，oneshot 应答。命令处理中的端口探测用 `std::net`，
//!   从任何线程（含监听器回调内）同步调用控制面都不会死锁。
//! - **supervisor 线程**（`luciola-tunnel-link`）：`new_current_thread`
//!   runtime + `block_on`，负责 tunnel端口的拨号/监听/接受、退避重建、
//!   Guard 生命周期与计数折叠。所有阻塞点均 `select!` 关停信号。
//!
//! ## 关键语义（spec T3/T4）
//!
//! - **懒建立**：注册任一转发或启用端点后才拨/监听 tunnel_port
//!   （`secure 端口 + 1`，`TunnelLink::set_tunnel_port` 显式覆盖）。
//! - **断链自动重建**：MuxSession 死亡 → 折叠计数 → 退避重建 → 按注册表
//!   恢复全部转发/端点；上层只看到 `ForwardStat::active` 变化。
//! - **注册表与基址跨重建存活**：pause（消息链路断开）只拆除活跃转发，
//!   `set_base`（connect/listen）恢复。
//! - **五类注册条目**（v2）：`locals`（Dial 侧本地 TCP 转发）、`udps`（Dial 侧
//!   UDP 转发）、`remote_endpoint`（Dial 侧接受 remote forward 的 ACL）、
//!   `endpoint`（Listen 侧拨入 ACL）、`remotes`（Listen 侧 remote forward）。
//!   角色校验：前三者要求 Dial 基址，后两者要求 Listen 基址。
//! - **上报**：`TunnelReporter::report` 的 kind 与
//!   `SecureSessionListener::on_state` 同构（"error" | "retrying"）。
//!   隧道不产生 "connected"/"closed"（消息链路已覆盖），活跃度走 stats。
//!
//! 锁序（全模块统一，防死锁）：`registry` 先于 `live`；任何锁持有期间
//! **禁止 await、禁止调用 reporter**。

mod api;
mod loops;
mod shared;
mod types;

pub use api::TunnelLink;
pub(crate) use loops::{cmd_loop, supervisor_thread};
pub use shared::ListenPort;
pub(crate) use shared::Shared;
pub(crate) use types::{
    Cmd, EndpointReg, EstablishOutcome, ForwardReg, Live, Registry, Reply, Snap, BACKOFF_INIT,
    BACKOFF_MAX, KEEPALIVE_DEFAULT,
};
pub use types::{ForwardKind, ForwardStat, TunnelBase, TunnelReporter};
