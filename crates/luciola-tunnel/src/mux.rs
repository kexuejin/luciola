//! mux —— 在一条 SecureStream 上复用多路 LAN TCP/UDP 通道。
//!
//! 帧格式 v1 不变：12 字节帧头 MX | ver 0x01 | type | ch_id(u32be) | payload_len(u32be)。
//! v2 能力全部落在原本「保留」的帧类型上，v1 对端把它们当未知保留帧忽略
//! （对 v1 发送 PING/WINDOW 是干净的 no-op），因此前后向兼容：
//!
//! - **keepalive（v2）**：会话启动即发探测 PING(nonce)，对端回 PONG(nonce)；
//!   收到任何 PING/PONG/WINDOW 即证明对端是 v2（`peer_v2`）。v2 对端之间
//!   `keepalive_dead_after` 静默超时终止会话（由上层重建）；v1 对端永不回
//!   PONG，因此**永不**被静默超时误杀（R7 边界保持）。
//! - **WINDOW 逐通道流控（v2）**：接收方消费 DATA 后回 WINDOW(delta)；
//!   发送方在 `peer_v2` 证明后执行窗口（outstanding ≥ window_size 即挂起），
//!   v1 对端维持 v1 语义（队列背压 + stall_hard_timeout，§1.4）。
//!   credit 帧与 EOF/CLOSE 同走可靠路径（队列满则延迟补发，不可丢）。
//! - **双向 OPEN（v2 remote forward，-R）**：v1 只有 Initiator 发 OPEN（奇数
//!   通道）；v2 中 Responder 也可发 OPEN（偶数通道），仅当 `peer_v2` 已证明
//!   ——否则按 D9 结构性违规终止（v1 对端收到偶数 OPEN 必死会话）。
//! - **数据报通道（v2 UDP 会话映射）**：新帧类型 T_DOPEN 打开数据报模式
//!   通道，每个 DATA 帧 = 一个 UDP 数据报（边界保留）；仅对已证明 v2 的
//!   对端发送/接受。空 DATA 帧在线上被丢弃，故 0 长数据报不可用（记录在案）。
//! - **主机名目标（v2）**：OPEN/DOPEN 的 host 字段本就是 utf8 文本；v2 接受
//!   合法主机名（结构校验），解析与钉扎由策略层（forward endpoint）完成。
//!
//! 不变的既有语义：
//!
//! - grant 先把通道置 Active、再写 ACK(0)（顺序反了会让对端在 ACK 前写入 DATA
//!   被判违规）；OPEN_ACK(非0) 是终态帧，只回收通道、不补发 CLOSE。
//! - 终止是幂等的：terminate(reason) 首次触发者生效，避免 CLOSE 互踢循环；
//!   会话级关闭 = CLOSE(type 0x05, ch_id 0, reason)。
//! - 级联停顿硬超时（§1.4）：通道入站队列 send 超过 stall_hard_timeout →
//!   只拆该通道（CLOSE(2)），会话与其余通道继续流动（对 v1 对端仍是唯一防线）。
//! - 控制帧不可丢：队列满时经 `Inner::defer_ctrl` 延迟串行补发（EOF/CLOSE/WINDOW）。
//! - poll_write 按部分写实现：每次最多接受 min(max_data_frame, 窗口余量) 字节。

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use luciola::link::secure::{SecureRecvHalf, SecureSendHalf, SecureStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

// ---------------------------------------------------------------- 协议常量

/// 帧头魔数（D9：坏 magic = 结构性违规，终止会话）。
pub const MAGIC: [u8; 2] = *b"MX";
/// 当前线协议版本。
pub const PROTO_VERSION: u8 = 0x01;
/// 帧头长度：magic(2) + ver(1) + type(1) + ch_id(4) + payload_len(4)。
pub const HEADER_LEN: usize = 12;
/// 协议 DATA 载荷上限（§1.1）。解码器按它校验；config.max_data_frame 只约束本地写入切片。
pub const MAX_DATA_FRAME: usize = 64 * 1024;

pub const T_OPEN: u8 = 0x01;
pub const T_ACK: u8 = 0x02;
pub const T_DATA: u8 = 0x03;
pub const T_EOF: u8 = 0x04;
pub const T_CLOSE: u8 = 0x05;
/// 会话级 keepalive 探测（v2；payload = 8 字节 nonce，ch_id 0）。v1 对端忽略。
pub const T_PING: u8 = 0x06;
/// PING 的应答（v2；payload = 回显 nonce，ch_id 0）。v1 对端忽略。
pub const T_PONG: u8 = 0x07;
/// 逐通道流控 credit（v2；payload = u32be 消费增量，ch_id = 通道）。v1 对端忽略。
pub const T_WINDOW: u8 = 0x08;
/// 数据报通道 OPEN（v2；payload 同 OPEN，ch_id 奇偶规则同 OPEN）。仅对 v2 对端发送。
pub const T_DOPEN: u8 = 0x09;

/// OPEN_ACK status（§1.1）。
pub struct AckStatus;
impl AckStatus {
    pub const OK: u8 = 0;
    pub const ACL_DENIED: u8 = 1;
    pub const DIAL_FAILED: u8 = 2;
    pub const CHANNEL_LIMIT: u8 = 3;
    pub const BAD_TARGET: u8 = 4;
}

/// CLOSE reason（§1.1）。
pub struct CloseReason;
impl CloseReason {
    pub const NORMAL: u8 = 0;
    pub const PROTOCOL_VIOLATION: u8 = 1;
    pub const UPSTREAM_RESET: u8 = 2;
    pub const SESSION_SHUTDOWN: u8 = 3;
}

// ---------------------------------------------------------------- 类型与错误

/// mux 角色（D8）：决定本端分配的通道 ID 奇偶——Initiator 奇数、Responder 偶数
/// （v2 起 Responder 也可发 OPEN，即 remote forward；奇偶规则不变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// 拨号目标：IP 字面量或主机名 + 端口（wire 上 host 是 utf8 文本，≤255 字节）。
///
/// 主机名只做结构校验；解析发生在拨号侧（forward endpoint），并按会话钉扎
/// （v2 防 rebinding：同一会话内同一主机名的解析结果复用）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialTarget {
    /// IP 字面量或主机名（构造时小写规范化、去尾部点）。
    pub host: String,
    pub port: u16,
}

impl DialTarget {
    /// 由 IP 构造（v1 兼容入口）。
    pub fn from_ip(host: IpAddr, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }

    pub fn from_addr(addr: std::net::SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    /// 由文本构造（IP 字面量或主机名）。规范化：小写、去单个尾点。
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let mut host: String = host.into().trim().to_lowercase();
        if host.ends_with('.') {
            host.pop();
        }
        Self { host, port }
    }

    /// host 是 IP 字面量时返回解析结果（主机名 → None）。
    pub fn ip_literal(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// 目标合法性（§1.2 bad_target 判定；解析阶段与 responder 侧 OPEN 校验共用）：
    ///
    /// - `port != 0`；
    /// - IP 字面量：非未指定、非组播、非 IPv4 广播（zone-id/方括号在 parse 即拒绝）；
    /// - 主机名：≤253 字节、标签 [alnum-]（≤63、不空、不以 `-` 开头/结尾）、
    ///   不含空白/冒号/方括号/百分号，且至少含一个字母（挡纯数字串冒充主机名）。
    pub fn validate(&self) -> bool {
        if self.port == 0 {
            return false;
        }
        if self.host.is_empty() || self.host.len() > 253 {
            return false;
        }
        if let Some(ip) = self.ip_literal() {
            if ip.is_unspecified() || ip.is_multicast() {
                return false;
            }
            if let IpAddr::V4(v4) = ip {
                if v4.is_broadcast() {
                    return false;
                }
            }
            return true;
        }
        let h = &self.host;
        if h.bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
        {
            return false;
        }
        for label in h.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
        }
        h.bytes().any(|b| b.is_ascii_alphabetic())
    }
}

impl fmt::Display for DialTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip_literal() {
            Some(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// mux 层错误（§2.2）。
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    /// 会话已终止：连接断开、对端 CLOSE(ch 0) 或本端 shutdown()。
    #[error("session closed")]
    SessionClosed,
    /// open() 在 open_timeout 内未收到 OPEN_ACK（已补发 CLOSE(upstream_reset)）。
    #[error("open timed out after {0:?}")]
    OpenTimeout(Duration),
    /// 对端 OPEN_ACK(非 0)：终态拒绝，通道已回收且不补发 CLOSE。
    #[error("open rejected by peer: status {status}, detail: {detail:?}")]
    Rejected { status: u8, detail: Option<String> },
    /// 目标不合法（§1.2 bad_target 判定，解析阶段拒绝）。
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    /// 结构性违规（D9）：坏 magic/ver/长度越界/未知类型等。
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// 通道已被回收（grant/deny 打在已死通道上）。
    #[error("channel closed")]
    ChannelClosed,
    /// grant/grant_datagram 与通道模式不匹配（流式通道打 grant_datagram 等）。
    #[error("channel mode mismatch")]
    ModeMismatch,
    /// 数据报超过单帧上限（MAX_DATA_FRAME）。
    #[error("datagram of {0} bytes exceeds MAX_DATA_FRAME {MAX_DATA_FRAME}")]
    DatagramTooLarge(usize),
    /// 对端未证明 v2 能力（从不回 PONG/WINDOW），本端能力依赖 v2 线语义（如
    /// Responder 发起 OPEN）被拒绝。
    #[error("peer did not prove v2 capability: {0}")]
    UnsupportedByPeer(&'static str),
    /// deny() 只接受 1..=4 的非 0 终态状态。
    #[error("invalid ACK status {0}")]
    InvalidAckStatus(u8),
}

/// 会话统计（forward 层 Guard 的 status 透出数据源之一）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MuxStats {
    /// 当前处于 Active 的通道数（含流式与数据报）。
    pub channels_open: usize,
    /// 会话生命周期内创建过的通道总数（两条角色各自累计）。
    pub channels_total: u64,
}

/// mux 会话/通道配置。默认值来自 spec §1.4/§2.2 与 v2 落地取值。
#[derive(Debug, Clone)]
pub struct MuxConfig {
    /// 单会话通道上限：超限回 OPEN_ACK(3)。UDP 会话映射每个源地址占一条通道。
    pub max_channels: usize,
    /// 单通道入站帧队列容量（帧数）。
    pub channel_queue_frames: usize,
    /// 单次 poll_write 最多接受的字节数（clamp 到 MAX_DATA_FRAME）。
    pub max_data_frame: usize,
    /// open() 等待 OPEN_ACK 的超时。
    pub open_timeout: Duration,
    /// forward 层拨号超时（T2 使用；mux 核心透传持有）。
    pub dial_timeout: Duration,
    /// 级联停顿硬超时（§1.4）：入站队列打满超过它只拆该通道。
    pub stall_hard_timeout: Duration,
    /// 逐通道流控窗口（字节，v2）。sanitize 后 ≥ max_data_frame。
    pub window_size: usize,
    /// keepalive PING 间隔（v2）；None = 关闭 keepalive。默认 15s。
    pub keepalive_interval: Option<Duration>,
    /// 对端静默判定阈值（v2）：仅当对端已证明 v2 且本端 keepalive 开启时执行；
    /// v1 对端永不触发。默认 45s。
    pub keepalive_dead_after: Option<Duration>,
    /// 流式通道空闲回收；None = 不回收（默认，空闲 SSH 类长连接不受影响）。
    pub idle_timeout: Option<Duration>,
    /// 数据报通道（UDP 会话映射）空闲回收；默认 60s（NAT 式映射必须回收）。
    pub udp_idle_timeout: Option<Duration>,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            max_channels: 32,
            channel_queue_frames: 8,
            max_data_frame: MAX_DATA_FRAME,
            open_timeout: Duration::from_secs(5),
            dial_timeout: Duration::from_secs(5),
            stall_hard_timeout: Duration::from_secs(10),
            window_size: 256 * 1024,
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_dead_after: Some(Duration::from_secs(45)),
            idle_timeout: None,
            udp_idle_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl MuxConfig {
    fn sanitized(mut self) -> Self {
        self.max_channels = self.max_channels.max(1);
        self.channel_queue_frames = self.channel_queue_frames.max(1);
        self.max_data_frame = self.max_data_frame.clamp(1, MAX_DATA_FRAME);
        // 窗口必须 ≥ 单帧上限，否则一帧永远发不出去（死锁）。
        self.window_size = self
            .window_size
            .max(self.max_data_frame)
            .min(4 * 1024 * 1024);
        if let (Some(i), Some(d)) = (self.keepalive_interval, self.keepalive_dead_after) {
            self.keepalive_dead_after = Some(d.max(i));
        }
        // Some(0) 视为关闭（None 才是显式关闭；0 直接归一）。
        self.idle_timeout = self.idle_timeout.filter(|d| !d.is_zero());
        self.udp_idle_timeout = self.udp_idle_timeout.filter(|d| !d.is_zero());
        self
    }
}

// ---------------------------------------------------------------- 帧编解码

/// 解码后的帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Open {
        ch_id: u32,
        host: String,
        port: u16,
    },
    /// 数据报通道 OPEN（v2 UDP 会话映射）；payload 与 OPEN 相同。
    DOpen {
        ch_id: u32,
        host: String,
        port: u16,
    },
    Ack {
        ch_id: u32,
        status: u8,
        detail: Option<String>,
    },
    Data {
        ch_id: u32,
        bytes: Vec<u8>,
    },
    Eof {
        ch_id: u32,
    },
    Close {
        ch_id: u32,
        reason: u8,
    },
    /// keepalive 探测（v2，ch_id 0）：收到即证明对端 v2，回 PONG(nonce)。
    Ping {
        nonce: u64,
    },
    /// PING 的应答（v2，ch_id 0）：收到即证明对端 v2。
    Pong {
        nonce: u64,
    },
    /// 逐通道流控 credit（v2）：对端消费了 delta 字节，本端 outstanding 递减。
    Window {
        ch_id: u32,
        delta: u32,
    },
}

/// 编码一帧。payload 不得超过 MAX_DATA_FRAME（DATA 分片在 poll_write 内完成）。
pub fn encode_frame(ftype: u8, ch_id: u32, payload: &[u8]) -> Vec<u8> {
    debug_assert!(
        payload.len() <= MAX_DATA_FRAME,
        "payload {} exceeds MAX_DATA_FRAME",
        payload.len()
    );
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len());
    v.extend_from_slice(&MAGIC);
    v.push(PROTO_VERSION);
    v.push(ftype);
    v.extend_from_slice(&ch_id.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn proto_err<T>(msg: impl Into<String>) -> Result<T, MuxError> {
    Err(MuxError::Protocol(msg.into()))
}

/// 解码一帧。结构性违规（坏 magic/版本/长度越界/截断/未知类型）→ Err(Protocol)，
/// 由读侧按 D9 终止会话；通道级语义（未知通道、待 ACK 数据等）在分发阶段判定。
pub fn decode_frame(buf: &[u8]) -> Result<Frame, MuxError> {
    if buf.len() < HEADER_LEN {
        return proto_err(format!("truncated frame header ({} bytes)", buf.len()));
    }
    if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
        return proto_err("bad magic");
    }
    if buf[2] != PROTO_VERSION {
        return proto_err(format!("unsupported version {}", buf[2]));
    }
    let ftype = buf[3];
    let ch_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let payload_len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
    if payload_len > MAX_DATA_FRAME {
        return proto_err(format!(
            "payload_len {} exceeds MAX_DATA_FRAME {}",
            payload_len, MAX_DATA_FRAME
        ));
    }
    if buf.len() < HEADER_LEN + payload_len {
        return proto_err(format!(
            "truncated frame: have {} want {}",
            buf.len(),
            HEADER_LEN + payload_len
        ));
    }
    let payload = &buf[HEADER_LEN..HEADER_LEN + payload_len];
    match ftype {
        T_OPEN | T_DOPEN => {
            if payload.is_empty() {
                return proto_err("open: empty payload");
            }
            let host_len = payload[0] as usize;
            if payload.len() != 1 + host_len + 2 {
                return proto_err("open: payload length mismatch");
            }
            let host = match std::str::from_utf8(&payload[1..1 + host_len]) {
                Ok(s) => s.to_string(),
                Err(_) => return proto_err("open: host is not utf8"),
            };
            let port = u16::from_be_bytes([payload[1 + host_len], payload[2 + host_len]]);
            if ftype == T_OPEN {
                Ok(Frame::Open { ch_id, host, port })
            } else {
                Ok(Frame::DOpen { ch_id, host, port })
            }
        }
        T_ACK => {
            if payload.is_empty() {
                return proto_err("ack: empty payload");
            }
            let status = payload[0];
            let detail = if payload.len() > 1 {
                let dlen = payload[1] as usize;
                if payload.len() != 2 + dlen {
                    return proto_err("ack: detail length mismatch");
                }
                Some(String::from_utf8_lossy(&payload[2..]).into_owned())
            } else {
                None
            };
            Ok(Frame::Ack {
                ch_id,
                status,
                detail,
            })
        }
        T_DATA => Ok(Frame::Data {
            ch_id,
            bytes: payload.to_vec(),
        }),
        T_EOF => {
            if !payload.is_empty() {
                return proto_err("eof: payload must be empty");
            }
            Ok(Frame::Eof { ch_id })
        }
        T_CLOSE => {
            if payload.len() != 1 {
                return proto_err("close: payload must be exactly one reason byte");
            }
            Ok(Frame::Close {
                ch_id,
                reason: payload[0],
            })
        }
        T_PING | T_PONG => {
            if payload.len() != 8 {
                return proto_err("ping/pong: payload must be an 8-byte nonce");
            }
            let nonce = u64::from_be_bytes(payload.try_into().unwrap());
            if ftype == T_PING {
                Ok(Frame::Ping { nonce })
            } else {
                Ok(Frame::Pong { nonce })
            }
        }
        T_WINDOW => {
            if ch_id == 0 {
                return proto_err("window: ch_id 0 is reserved (per-channel only)");
            }
            if payload.len() != 4 {
                return proto_err("window: payload must be a 4-byte delta");
            }
            Ok(Frame::Window {
                ch_id,
                delta: u32::from_be_bytes(payload.try_into().unwrap()),
            })
        }
        other => proto_err(format!("unknown frame type {:#04x}", other)),
    }
}

fn encode_open_payload(target: &DialTarget) -> Vec<u8> {
    let host = target.host.as_bytes();
    debug_assert!(host.len() <= u8::MAX as usize, "host too long");
    let mut p = Vec::with_capacity(1 + host.len() + 2);
    p.push(host.len() as u8);
    p.extend_from_slice(host);
    p.extend_from_slice(&target.port.to_be_bytes());
    p
}

fn encode_ack_payload(status: u8, detail: Option<&str>) -> Vec<u8> {
    let mut p = vec![status];
    // §1.1：acl_denied 不附 detail（不泄漏策略）；其余状态可附诊断串。
    if status != AckStatus::ACL_DENIED {
        if let Some(d) = detail {
            let d = d.as_bytes();
            let n = d.len().min(255);
            p.push(n as u8);
            p.extend_from_slice(&d[..n]);
        }
    }
    p
}

/// wire 侧目标解析：只做结构校验（IP 字面量规则或主机名规则，§1.2）。
/// 主机名的 DNS 解析在策略层（forward endpoint）完成，mux 核心不做 IO。
fn parse_open_target(host: &str, port: u16) -> Option<DialTarget> {
    let t = DialTarget::new(host, port);
    t.validate().then_some(t)
}

// ---------------------------------------------------------------- 内部状态

/// 通道模式：流式（TCP 语义）或数据报（UDP 语义，DATA 帧 = 一个数据报）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanMode {
    Stream,
    Datagram,
}

/// 队列内部：入站通道消息。
#[derive(Debug)]
enum MuxInbound {
    Data(Vec<u8>),
    Eof,
    /// 对端 CLOSE(ch) —— reason=0 视为读端正常结束。
    Close(u8),
    /// 会话终止：所有通道同步置错。
    SessionDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Active,
}

/// open() 等待 OPEN_ACK 的结果：Ok(0 经 grant) / Err((status, detail))。
type AckOutcome = Result<(), (u8, Option<String>)>;

/// 逐通道流控状态（v2 WINDOW）。会话与 MuxStream/MuxDatagram 共享。
struct FlowState {
    /// 已发出但未获对端 WINDOW credit 确认的字节数。与 waker 同锁：
    /// poll_write 的「检查窗口 + 登记 waker」与 reader 的「减 credit + 唤醒」互斥。
    send: StdMutex<SendWindow>,
    /// 已消费、待上报给对端的字节数（credit 阈值触发 WINDOW 帧）。
    unacked: AtomicU64,
    /// 异步等待方（send_datagram）的唤醒器。
    wake: Notify,
    /// 最近活动时刻（epoch 毫秒）；idle reaper 依据。
    last_active_ms: AtomicU64,
}

#[derive(Default)]
struct SendWindow {
    outstanding: u64,
    waker: Option<Waker>,
}

impl FlowState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            send: StdMutex::new(SendWindow::default()),
            unacked: AtomicU64::new(0),
            wake: Notify::new(),
            last_active_ms: AtomicU64::new(0),
        })
    }

    /// peer_v2 证明时刻的钳制：证明前未执行窗口，outstanding 可能已超限。
    fn clamp(&self, window: u64) {
        let mut s = self.send.lock().unwrap();
        s.outstanding = s.outstanding.min(window);
    }

    fn touch(&self, now_ms: u64) {
        self.last_active_ms.store(now_ms, Ordering::Relaxed);
    }

    /// 通道/会话终止：唤醒所有等窗口的写方（park 的 poll_write waker 与
    /// send_datagram 的 Notify 等待者）。漏掉 waker 会让写方在窗口耗尽 +
    /// 通道死亡的组合下永久挂起。
    fn kill(&self) {
        let w = self.send.lock().unwrap().waker.take();
        if let Some(w) = w {
            w.wake();
        }
        self.wake.notify_waiters();
    }
}

struct Entry {
    state: State,
    mode: ChanMode,
    in_tx: mpsc::Sender<MuxInbound>,
    /// 通道与 MuxStream/MuxDatagram 共享：置位后 poll_read/poll_write 直接报错。
    dead: Arc<AtomicBool>,
    /// 流控状态（v2）。
    flow: Arc<FlowState>,
    /// 仅发起方 pending 时持有（open()/open_datagram() 的 oneshot 另一端）。
    ack: Option<oneshot::Sender<AckOutcome>>,
}

struct Inner {
    cfg: MuxConfig,
    role: Role,
    table: StdMutex<HashMap<u32, Entry>>,
    /// Initiator 分配奇数 ch_id（1,3,5,…），Responder 分配偶数（2,4,6,…，v2）；
    /// 单调不复用（D8）。
    next_ch: AtomicU32,
    alive: AtomicBool,
    /// 对端已证明 v2 能力（收到过 PING/PONG/WINDOW 之一）。证明前：偶数通道帧
    /// 仍按 v1 判违规、本端（Responder）不执行窗口、Responder 不得发 OPEN。
    peer_v2: AtomicBool,
    /// 会话级 CLOSE(ch 0) 由对端线帧触发（对端主动关闭）。传输层 FIN/错误
    /// 直接 terminate 不置位——上层（CLI 监督循环）据此区分"对端关闭 → 优雅退出"与
    /// "链路断开 → 退避重建"（T2 链路引导契约）。
    peer_close: AtomicBool,
    opened_total: AtomicU64,
    ctrl_tx: mpsc::Sender<Vec<u8>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    open_req_tx: mpsc::Sender<OpenRequest>,
    open_req_rx: AsyncMutex<Option<mpsc::Receiver<OpenRequest>>>,
    /// 会话终止原因；None = 存活。首次 terminate 生效（幂等）。
    term: watch::Sender<Option<u8>>,
    /// 队列满时延迟发送的通道控制帧（EOF/drop-CLOSE/WINDOW credit）。
    /// 统一队列被 DATA 背压占满时 try_send 会失败——半关闭帧或 credit 丢失会让
    /// 对端永久等待，故转延迟队列补发。
    deferred_ctrl: StdMutex<VecDeque<Vec<u8>>>,
    /// 延迟补发任务是否在跑。与 deferred_ctrl 同锁读写：单任务串行保证同通道保序。
    defer_active: AtomicBool,
    /// 会话所在 tokio 运行时（start 在 runtime 上下文内调用——调度契约，lib.rs 文档）。
    handle: tokio::runtime::Handle,
    /// 会话起始时刻（Idle/keepalive 的毫秒时钟基准）。
    epoch: Instant,
    /// 最近一次从 wire 收到帧的时刻（epoch 毫秒；reader 更新）。
    last_recv_ms: AtomicU64,
    /// 最近一次向 wire 写出帧的时刻（epoch 毫秒；writer 更新）。
    last_send_ms: AtomicU64,
    /// PING nonce 计数器（探测/周期 PING 用；无加密意义）。
    ping_counter: AtomicU64,
}

fn now_ms(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}

impl Inner {
    /// 会话级终止（§1.3）：置 alive=false（首触发者生效）→ 逐通道拆除并
    /// 唤醒 accept_open/open/MuxStream → 由 writer 发出最终 CLOSE(reason, ch 0) 后关闭写半区。
    fn terminate(&self, reason: u8) {
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
    fn defer_ctrl(self: &Arc<Self>, frame: Vec<u8>) {
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
    fn set_peer_v2(&self) {
        if self.peer_v2.swap(true, Ordering::SeqCst) {
            return;
        }
        let window = self.cfg.window_size as u64;
        let table = self.table.lock().unwrap();
        for entry in table.values() {
            entry.flow.clamp(window);
        }
    }
}

/// 若表内条目仍是 dead 指向的那一个，则移除并置位 dead（可选向通道队列推一条终态消息）。
fn remove_entry(inner: &Inner, ch_id: u32, dead: &Arc<AtomicBool>, push: Option<MuxInbound>) {
    let mut table = inner.table.lock().unwrap();
    let is_same = table
        .get(&ch_id)
        .map(|e| Arc::ptr_eq(&e.dead, dead))
        .unwrap_or(false);
    if is_same {
        if let Some(entry) = table.remove(&ch_id) {
            entry.dead.store(true, Ordering::SeqCst);
            if let Some(msg) = push {
                let _ = entry.in_tx.try_send(msg);
            }
            entry.flow.kill();
        }
    }
}

// ---------------------------------------------------------------- OpenRequest

/// accept_open() 返回的待决请求（§2.2）。grant/deny 至少调用一个；
/// 未答复即 Drop → 自动 deny(2)（open_timeout 到期对端会收到终态帧）。
pub struct OpenRequest {
    pub target: DialTarget,
    pub ch_id: u32,
    /// true = 数据报通道（DOPEN，UDP 会话映射）：用 grant_datagram() 应答。
    pub datagram: bool,
    rx: Option<mpsc::Receiver<MuxInbound>>,
    inner: Arc<Inner>,
    answered: bool,
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
fn entry_dead_marker(inner: &Inner, ch_id: u32) -> Arc<AtomicBool> {
    let table = inner.table.lock().unwrap();
    table
        .get(&ch_id)
        .map(|e| e.dead.clone())
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
}

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
                    in_tx,
                    dead: dead.clone(),
                    flow,
                    ack: Some(ack_tx),
                },
            );
        }
        inner.opened_total.fetch_add(1, Ordering::SeqCst);

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

// ---------------------------------------------------------------- 读任务

async fn reader_loop(
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
async fn handle_frame(inner: &Arc<Inner>, frame: Frame) -> Result<(), ()> {
    match frame {
        Frame::Ping { nonce } => {
            // v2 能力证明 + keepalive 应答（v1 对端不会发 PING，也不会回 PONG）
            inner.set_peer_v2();
            send_ctrl(inner, encode_frame(T_PONG, 0, &nonce.to_be_bytes())).await;
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
async fn handle_open(
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
            send_ctrl(inner, encode_frame(T_ACK, ch_id, &payload)).await;
            return Ok(());
        }
    };
    let (in_tx, in_rx) = mpsc::channel(inner.cfg.channel_queue_frames);
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
                        in_tx,
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
            )
            .await;
            return Ok(());
        }
        Admit::Dup => {
            // 重复 ch_id：不复用旧通道，回 OPEN_ACK(4)（§1.2 bad_target）
            let payload = encode_ack_payload(AckStatus::BAD_TARGET, Some("duplicate channel id"));
            send_ctrl(inner, encode_frame(T_ACK, ch_id, &payload)).await;
            return Ok(());
        }
        Admit::Pass => {}
    }
    inner.opened_total.fetch_add(1, Ordering::SeqCst);
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
        )
        .await;
    }
    Ok(())
}

/// 通道级数据/Eof 分发：Active 投递、Pending 即违规（OPEN_ACK 前发数据）、
/// 未知通道丢弃且只回 CLOSE(0)（D9，不杀会话）。
async fn deliver_dispatch(inner: &Arc<Inner>, ch_id: u32, msg: MuxInbound) -> Result<(), ()> {
    enum Target {
        Channel(mpsc::Sender<MuxInbound>, Arc<AtomicBool>, Arc<FlowState>),
        Pending,
        Unknown,
    }
    let target = {
        let table = inner.table.lock().unwrap();
        match table.get(&ch_id) {
            Some(entry) => match entry.state {
                State::Active => {
                    Target::Channel(entry.in_tx.clone(), entry.dead.clone(), entry.flow.clone())
                }
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
        Target::Channel(in_tx, dead, flow) => {
            deliver(inner, ch_id, dead, flow, in_tx, msg).await;
            Ok(())
        }
    }
}

/// 投递到通道队列，带级联停顿硬超时（§1.4）：超时只拆该通道（CLOSE(2)），会话继续。
async fn deliver(
    inner: &Inner,
    ch_id: u32,
    dead: Arc<AtomicBool>,
    flow: Arc<FlowState>,
    in_tx: mpsc::Sender<MuxInbound>,
    msg: MuxInbound,
) {
    // 入站流量即通道活动（UDP 映射语义：任一方向有包就续期）。
    flow.touch(now_ms(inner.epoch));
    match tokio::time::timeout(inner.cfg.stall_hard_timeout, in_tx.send(msg)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            // 本地通道端已被丢弃：回收条目（Drop 已补发 CLOSE(0)）
            remove_entry(inner, ch_id, &dead, None);
        }
        Err(_) => {
            warn!(
                "mux channel {ch_id} stalled > {:?} — tearing down channel only (§1.4)",
                inner.cfg.stall_hard_timeout
            );
            remove_entry(inner, ch_id, &dead, None);
            let _ = inner.ctrl_tx.try_send(encode_frame(
                T_CLOSE,
                ch_id,
                &[CloseReason::UPSTREAM_RESET],
            ));
        }
    }
}

/// 应用对端 WINDOW credit：outstanding 递减并唤醒挂起的写方。
fn apply_credit(flow: &Arc<FlowState>, delta: u32) {
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
fn send_credit(inner: &Arc<Inner>, ch_id: u32, flow: &Arc<FlowState>, n: usize) {
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

async fn send_ctrl(inner: &Inner, frame: Vec<u8>) {
    if inner.ctrl_tx.send(frame).await.is_err() {
        debug!("control queue closed (writer exited)");
    }
}

// ---------------------------------------------------------------- 写任务

async fn writer_loop(
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
async fn keepalive_loop(inner: Arc<Inner>, mut term_rx: watch::Receiver<Option<u8>>) {
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

fn send_ping(inner: &Inner) {
    let nonce = inner.ping_counter.fetch_add(1, Ordering::SeqCst);
    let _ = inner
        .ctrl_tx
        .try_send(encode_frame(T_PING, 0, &nonce.to_be_bytes()));
}

/// 通道空闲回收（v2）：按模式检查 last_active，超时只拆该通道（CLOSE(0)，
/// 对端读端表现为 EOF），会话与其余通道继续。Pending 通道由 open_timeout 管理，
/// 不参与回收。无任何回收配置时本任务直接退出。
async fn idle_reaper(inner: Arc<Inner>, mut term_rx: watch::Receiver<Option<u8>>) {
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
    fn new(
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

    /// 把消费量上报为对端窗口 credit（v2）。
    fn credit(&self, n: usize) {
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
    fn new(
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
                    _ = self.flow.wake.notified() => {}
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

// ---------------------------------------------------------------- 单元测试（编解码）

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip_open() {
        let target = DialTarget::from_ip("127.0.0.1".parse().unwrap(), 3080);
        let f = encode_frame(T_OPEN, 1, &encode_open_payload(&target));
        assert_eq!(f.len(), HEADER_LEN + 1 + 9 + 2);
        let dec = decode_frame(&f).unwrap();
        assert_eq!(
            dec,
            Frame::Open {
                ch_id: 1,
                host: "127.0.0.1".into(),
                port: 3080
            }
        );
    }

    #[test]
    fn codec_roundtrip_ipv6_target() {
        let target = DialTarget::from_ip("fe80::1".parse().unwrap(), 80);
        let f = encode_frame(T_OPEN, 3, &encode_open_payload(&target));
        match decode_frame(&f).unwrap() {
            Frame::Open { ch_id, host, port } => {
                assert_eq!(ch_id, 3);
                assert_eq!(host, "fe80::1"); // 裸字面量，无方括号（§1.1）
                assert_eq!(port, 80);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn codec_roundtrip_dopen_and_v2_frames() {
        let target = DialTarget::new("nas.local", 5353);
        let f = encode_frame(T_DOPEN, 2, &encode_open_payload(&target));
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::DOpen {
                ch_id: 2,
                host: "nas.local".into(),
                port: 5353
            }
        );

        let f = encode_frame(T_PING, 0, &12345u64.to_be_bytes());
        assert_eq!(decode_frame(&f).unwrap(), Frame::Ping { nonce: 12345 });
        let f = encode_frame(T_PONG, 0, &12345u64.to_be_bytes());
        assert_eq!(decode_frame(&f).unwrap(), Frame::Pong { nonce: 12345 });
        let f = encode_frame(T_WINDOW, 7, &4096u32.to_be_bytes());
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::Window {
                ch_id: 7,
                delta: 4096
            }
        );
    }

    #[test]
    fn v2_frame_shape_violations_are_structural() {
        // PING 载荷不是 8 字节 nonce
        let f = encode_frame(T_PING, 0, &[0; 4]);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
        // WINDOW 载荷不是 4 字节
        let f = encode_frame(T_WINDOW, 1, &[0; 8]);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
        // WINDOW 打在会话级 ch 0
        let f = encode_frame(T_WINDOW, 0, &1u32.to_be_bytes());
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
        // 未知类型仍结构违规
        let f = encode_frame(0x7f, 1, &[1]);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
    }

    #[test]
    fn codec_roundtrip_data_eof_close() {
        let f = encode_frame(T_DATA, 7, &[0u8, 1, 2, 255]);
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::Data {
                ch_id: 7,
                bytes: vec![0, 1, 2, 255]
            }
        );

        let f = encode_frame(T_EOF, 9, &[]);
        assert_eq!(decode_frame(&f).unwrap(), Frame::Eof { ch_id: 9 });

        let f = encode_frame(T_CLOSE, 0, &[CloseReason::SESSION_SHUTDOWN]);
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::Close {
                ch_id: 0,
                reason: 3
            }
        );
    }

    #[test]
    fn codec_roundtrip_ack_with_and_without_detail() {
        let f = encode_frame(T_ACK, 1, &encode_ack_payload(AckStatus::OK, None));
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::Ack {
                ch_id: 1,
                status: 0,
                detail: None
            }
        );

        let f = encode_frame(
            T_ACK,
            1,
            &encode_ack_payload(AckStatus::DIAL_FAILED, Some("no route")),
        );
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::Ack {
                ch_id: 1,
                status: 2,
                detail: Some("no route".into())
            }
        );

        // §1.1：acl_denied 不附 detail，即使尝试附带也在编码期丢弃
        let f = encode_frame(
            T_ACK,
            1,
            &encode_ack_payload(AckStatus::ACL_DENIED, Some("secret")),
        );
        assert_eq!(
            decode_frame(&f).unwrap(),
            Frame::Ack {
                ch_id: 1,
                status: 1,
                detail: None
            }
        );
    }

    #[test]
    fn decode_rejects_bad_magic_version() {
        let mut f = encode_frame(T_DATA, 1, &[1, 2, 3]);
        f[0] = b'X';
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));

        let mut f = encode_frame(T_DATA, 1, &[1, 2, 3]);
        f[2] = 0x02;
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
    }

    #[test]
    fn decode_rejects_oversized_payload_length() {
        // payload_len 声明 64KiB+1，即使真实缓冲更短也在分配前被拒绝（D9 长度越界）
        let mut f = encode_frame(T_DATA, 1, &[1, 2, 3]);
        let big = (MAX_DATA_FRAME as u32 + 1).to_be_bytes();
        f[8..12].copy_from_slice(&big);
        let err = decode_frame(&f).unwrap_err();
        assert!(matches!(err, MuxError::Protocol(ref m) if m.contains("exceeds MAX_DATA_FRAME")));
    }

    #[test]
    fn decode_rejects_truncation() {
        let f = encode_frame(T_DATA, 1, &[1, 2, 3]);
        assert!(matches!(
            decode_frame(&f[..HEADER_LEN + 2]),
            Err(MuxError::Protocol(_))
        ));
        assert!(matches!(decode_frame(&f[..4]), Err(MuxError::Protocol(_))));
    }

    #[test]
    fn decode_rejects_malformed_payload_shapes() {
        // EOF 带载荷
        let f = encode_frame(T_EOF, 1, &[0]);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
        // CLOSE 不止一个 reason 字节
        let f = encode_frame(T_CLOSE, 1, &[0, 1]);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
        // OPEN host_len 与载荷长度不匹配
        let mut p = encode_open_payload(&DialTarget::from_ip("127.0.0.1".parse().unwrap(), 80));
        p[0] = 200;
        let f = encode_frame(T_OPEN, 1, &p);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
        // ACK detail 长度不匹配
        let f = encode_frame(T_ACK, 1, &[AckStatus::DIAL_FAILED, 9, b'x']);
        assert!(matches!(decode_frame(&f), Err(MuxError::Protocol(_))));
    }

    #[test]
    fn target_validation_matches_bad_target_rules() {
        let ok = |h: &str, p: u16| DialTarget::new(h, p).validate();
        assert!(ok("127.0.0.1", 3080));
        assert!(ok("192.168.1.7", 1));
        assert!(ok("::1", 80));
        assert!(ok("nas.local", 80));
        assert!(ok("My-NAS.Example.COM", 80)); // 构造时小写规范化
        assert!(!ok("127.0.0.1", 0)); // port=0
        assert!(!ok("0.0.0.0", 80)); // 未指定
        assert!(!ok("::", 80));
        assert!(!ok("224.0.0.1", 80)); // 组播
        assert!(!ok("ff02::1", 80));
        assert!(!ok("255.255.255.255", 80)); // 广播
        assert!(!ok("", 80)); // 空
        assert!(!ok("1.2.3.999", 80)); // 纯数字串冒充主机名
        assert!(!ok("-bad.example", 80)); // 标签以 - 开头
        assert!(!ok("bad..example", 80)); // 空标签
        assert!(!ok("has space.example", 80)); // 空白
        assert!(!ok("v6:zone", 80)); // 冒号（IPv6 必须走字面量路径）
                                     // 方括号/zone 形式不是合法 IP 字面量，parse 即失败
        assert!("[::1]:80".parse::<IpAddr>().is_err());
        assert!("fe80::1%eth0".parse::<IpAddr>().is_err());
    }

    #[test]
    fn dial_target_normalizes() {
        assert_eq!(DialTarget::new("NAS.Local.", 80).host, "nas.local");
        assert_eq!(
            DialTarget::from_ip("::ffff:127.0.0.1".parse().unwrap(), 80).host,
            "::ffff:127.0.0.1"
        );
        assert_eq!(
            DialTarget::from_ip("::ffff:127.0.0.1".parse().unwrap(), 80).ip_literal(),
            Some("::ffff:127.0.0.1".parse().unwrap())
        );
    }
}
