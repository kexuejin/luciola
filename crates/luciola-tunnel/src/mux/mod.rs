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
//! - 级联停顿硬超时（§1.4）：通道入站帧队列由**该通道自己的转发任务**写入，
//!   打满超过 stall_hard_timeout 只拆该通道（CLOSE(2)），会话与其余通道继续
//!   流动（对 v1 对端仍是唯一防线）。共享 read 任务只把帧放进取字节预算的
//!   暂存队列，**绝不同步等待单通道队列**——否则一条停顿通道会把整条会话
//!   （含其他通道的 OPEN/ACK/DATA）串行化：Windows 默认 socket 缓冲比
//!   macOS/Linux 小，实测可堵 >1s，超过 open_timeout 就让别的通道假超时。
//! - 控制帧不可丢：队列满时经 `Inner::defer_ctrl` 延迟串行补发（PONG/ACK/EOF/CLOSE/WINDOW），
//!   共享 read 任务内绝不 await 出站队列。
//! - poll_write 按部分写实现：每次最多接受 min(max_data_frame, 窗口余量) 字节。

mod protocol;
mod session;
mod state;
mod stream;
mod tasks;

pub use protocol::{
    decode_frame, encode_frame, AckStatus, CloseReason, DialTarget, Frame, MuxConfig, MuxError,
    MuxStats, Role, HEADER_LEN, MAX_DATA_FRAME, T_ACK, T_CLOSE, T_DATA, T_DOPEN, T_EOF, T_OPEN,
    T_PING, T_PONG, T_WINDOW,
};
pub(crate) use protocol::{encode_ack_payload, encode_open_payload, parse_open_target};
pub use session::MuxSession;
pub use state::ChanMode;
pub use state::OpenRequest;
pub(crate) use state::{now_ms, remove_entry, Entry, FlowState, Inner, MuxInbound, State};
pub use stream::{MuxDatagram, MuxStream};
pub(crate) use tasks::{
    channel_forwarder, idle_reaper, keepalive_loop, reader_loop, send_credit, writer_loop,
};
