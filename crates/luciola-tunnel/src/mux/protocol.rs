use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

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
    pub(crate) fn sanitized(mut self) -> Self {
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

pub(crate) fn proto_err<T>(msg: impl Into<String>) -> Result<T, MuxError> {
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

pub(crate) fn encode_open_payload(target: &DialTarget) -> Vec<u8> {
    let host = target.host.as_bytes();
    debug_assert!(host.len() <= u8::MAX as usize, "host too long");
    let mut p = Vec::with_capacity(1 + host.len() + 2);
    p.push(host.len() as u8);
    p.extend_from_slice(host);
    p.extend_from_slice(&target.port.to_be_bytes());
    p
}

pub(crate) fn encode_ack_payload(status: u8, detail: Option<&str>) -> Vec<u8> {
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
pub(crate) fn parse_open_target(host: &str, port: u16) -> Option<DialTarget> {
    let t = DialTarget::new(host, port);
    t.validate().then_some(t)
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
