use clap::{Parser, Subcommand};
use luciola::link::bind_dual_stack_listener;
use luciola::link::secure::{accept_secure, connect_secure_raced};
use luciola::{DiscoveryConfig, DiscoveryEngine, PeerEvent};
use luciola_tunnel::{
    start_forward_endpoint, start_local_forward, DialTarget, ForwardAcl, ForwardRule,
    LocalForwardConfig, MuxConfig, MuxSession, Role,
};
use std::net::IpAddr;
use std::sync::Arc;
use luciola_net::NetworkDetector;
use luciola_proto::Profile;
use qrcode::render::unicode;
use qrcode::QrCode;
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tracing_subscriber::EnvFilter;

/// Render a UTF-8 compact QR code for terminal display.
///
/// In standard dark-background developer terminals, foreground is white/light and background is black/dark.
/// Therefore, QR dark modules must be mapped to Dense1x2::Light (spaces/background = black) and
/// QR light modules/margins must be mapped to Dense1x2::Dark (full blocks/foreground = white).
pub fn render_qr_terminal(content: &str) -> Option<String> {
    let code = QrCode::new(content.as_bytes()).ok()?;
    let string = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    Some(string)
}

#[derive(Parser)]
#[command(name = "luciola")]
#[command(about = "Luciola: resilient LAN peer discovery and interface intelligence", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan and radar for nearby peers in the local network
    Scan {
        #[arg(short, long, default_value_t = 17878)]
        port: u16,
        #[arg(short, long, default_value_t = 10)]
        timeout_secs: u64,
    },
    /// Broadcast presence beacon so other peers can discover you
    Beacon {
        #[arg(short, long, default_value = "Luciola Node")]
        name: String,
        #[arg(short, long, default_value_t = 17878)]
        port: u16,
        /// Print terminal QR code for instant mobile pairing
        #[arg(long)]
        qr: bool,
    },
    /// Run the per-device discovery agent: owns UDP 17878 for the whole
    /// machine and streams peer events to local products over a unix socket
    /// (the desktop answer to several luciola products on one device).
    Agent {
        /// Unix socket path (default: $TMPDIR/luciola-agent.sock)
        #[arg(long)]
        socket: Option<String>,
        #[arg(short, long, default_value_t = 17878)]
        port: u16,
    },
    /// Inspect local network interfaces, TUN detection, and candidate IPs
    Ip {
        /// Render terminal QR code for the top local LAN IP
        #[arg(long)]
        qr: bool,
        /// Port to use in QR URL (default: 8080)
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
    /// 端口隧道：secure 链路上的 LAN TCP 转发（the tunnel plan r4 §2.3）
    Forward {
        #[command(subcommand)]
        action: ForwardCommands,
    },
}

#[derive(Subcommand)]
enum ForwardCommands {
    /// Responder：监听隧道端口，按 ACL 白名单为对端拨号本机目标
    Serve {
        /// 隧道监听端口（0 = 系统分配）
        #[arg(long, default_value_t = 3001)]
        tunnel_port: u16,
        /// 本端身份种子（hex，32 字节）
        #[arg(long)]
        seed: String,
        /// 对端公钥 pin（32 字节原文 hex；"forward pin --seed" 可推导）。缺省即拒绝，无 TOFU
        #[arg(long)]
        pin_peer: String,
        /// 允许拨号的目标白名单（可多次）：IP:PORT 或 IP:FROM-TO；缺省全拒绝
        #[arg(long = "allow", required = true)]
        allow: Vec<String>,
    },
    /// Initiator：本机 127.0.0.1:listen → 对端隧道 → target
    Dial {
        /// 本机监听端口（仅 127.0.0.1；0 = 系统分配）
        #[arg(long, default_value_t = 3080)]
        listen: u16,
        /// 对端隧道地址 host:port
        #[arg(long)]
        connect: String,
        /// 经隧道到达的目标地址 IP:PORT（对端机上）
        #[arg(long)]
        target: String,
        /// 本端身份种子（hex，32 字节）
        #[arg(long)]
        seed: String,
        /// 对端公钥 pin（32 字节原文 hex；"forward pin --seed" 可推导）
        #[arg(long)]
        pin_peer: String,
    },
    /// 从身份种子推导公钥 / 指纹 / 短码（供对端 --pin-peer 与配对展示）
    Pin {
        /// 本端身份种子（hex，32 字节）
        #[arg(long)]
        seed: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { port, timeout_secs } => {
            println!(
                "🔍 Scanning for peers on port {} (timeout: {}s)...",
                port, timeout_secs
            );
            let config = DiscoveryConfig {
                listen_port: 0, // Random ephemeral port to avoid conflict
                broadcast_port: port,
                ..Default::default()
            };

            let engine = DiscoveryEngine::bind(config).await?;
            let mut events = engine.subscribe();
            engine.clone().spawn();

            // Broadcast entry to request peers
            engine.announce().await;

            let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
            loop {
                tokio::select! {
                    Ok(event) = events.recv() => {
                        match event {
                            PeerEvent::Found(peer) => {
                                let (icon, desc) = match &peer.device {
                                    Some(d) => (d.device_type.icon(), format!(" [{} / {}]", d.os, d.model.as_deref().unwrap_or(&d.arch))),
                                    None => ("✨", String::new()),
                                };
                                println!("{} [FOUND] Node: {}{} ({}) @ {}:{}", icon, peer.name, desc, peer.node_id, peer.ip, peer.udp_port);
                            }
                            PeerEvent::Updated(peer) => {
                                println!("🔄 [UPDATED] Node: {} ({}) @ {}:{}", peer.name, peer.node_id, peer.ip, peer.udp_port);
                            }
                            PeerEvent::Lost(id) => {
                                println!("💨 [LOST] Node {} went offline", id);
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        println!("⏱️ Scan completed.");
                        break;
                    }
                }
            }
        }
        Commands::Beacon { name, port, qr } => {
            let node_id = format!("luciola_{:x}", rand::random::<u32>());
            println!(
                "📢 Broadcasting beacon as '{}' ({}) on port {}...",
                name, node_id, port
            );

            let candidates = NetworkDetector::local_candidate_addresses();
            let profile = Profile {
                node_id: node_id.clone(),
                name,
                profile_rev: 1,
                addresses: candidates.clone(),
                udp_port: port,
                tcp_port: port + 1,
                device: Some(luciola_net::DeviceDetector::detect()),
                device_id: None,
                product: None,
                extra: None,
                public_key: None,
            };

            if qr {
                if let Some(best_ip) = candidates.first() {
                    let url = if best_ip.contains(':') {
                        format!("http://[{}]:{}", best_ip, port + 1)
                    } else {
                        format!("http://{}:{}", best_ip, port + 1)
                    };
                    println!("\n📱 Scan with your phone to connect:");
                    println!("👉 URL: {}", url);
                    if let Some(qr_art) = render_qr_terminal(&url) {
                        println!("\n{}", qr_art);
                    }
                }
            }

            let config = DiscoveryConfig {
                self_profile: profile,
                listen_port: port,
                broadcast_port: port,
                presence_interval: Duration::from_secs(3),
                ..Default::default()
            };

            let engine = DiscoveryEngine::bind(config).await?;
            let mut events = engine.subscribe();
            engine.clone().spawn();

            engine.announce().await;
            println!("🚀 Beacon active. Press Ctrl+C to exit.");

            tokio::spawn(async move {
                while let Ok(event) = events.recv().await {
                    if let PeerEvent::Found(peer) = event {
                        println!("👋 Discovered neighbor: {} @ {}", peer.name, peer.ip);
                    }
                }
            });

            tokio::signal::ctrl_c().await?;
            println!("\n👋 Shutting down, sending exit announcement...");
            engine.announce_exit().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Commands::Agent { socket, port } => {
            let path = socket.unwrap_or_else(|| {
                std::env::var("TMPDIR")
                    .or_else(|_| std::env::var("XDG_RUNTIME_DIR"))
                    .map(|d| format!("{d}/luciola-agent.sock"))
                    .unwrap_or_else(|_| "/tmp/luciola-agent.sock".to_string())
            });
            run_agent(&path, port).await?;
        }
        Commands::Ip { qr, port } => {
            println!("========================================================");
            println!("       Luciola Network Interface & Route Intelligence    ");
            println!("========================================================");

            let device_meta = luciola_net::DeviceDetector::detect();
            println!("\n[0] Local Device Hardware Identity:");
            if let Some(ref name) = device_meta.hostname {
                println!("  🏷️  Friendly Device Name: {}", name);
            }
            if let Some(ref model) = device_meta.model {
                println!("  💻 Hardware Model: {}", model);
            }
            println!(
                "  {} Form Factor: {:?} ({})",
                device_meta.device_type.icon(),
                device_meta.device_type,
                device_meta.device_type.as_str()
            );
            println!(
                "  🌐 OS & Architecture: {} ({})",
                device_meta.os, device_meta.arch
            );

            println!("\n[1] Subnet Broadcast Targets (Bypassing Clash/TUN 0.0.0.0/1 capture):");
            let broadcasts = NetworkDetector::subnet_broadcast_addresses();
            if broadcasts.is_empty() {
                println!("  (None found)");
            } else {
                for b in broadcasts {
                    println!("  👉 Subnet broadcast: {}", b);
                }
            }

            println!("\n[2] Clean Local Candidate IPs (For QR code and LAN discovery):");
            let candidates = NetworkDetector::local_candidate_addresses();
            if candidates.is_empty() {
                println!("  (None found)");
            } else {
                for (idx, c) in candidates.iter().enumerate() {
                    println!("  [{}] {}", idx + 1, c);
                }
            }

            if qr {
                if let Some(best_ip) = candidates.first() {
                    let url = if best_ip.contains(':') {
                        format!("http://[{}]:{}", best_ip, port)
                    } else {
                        format!("http://{}:{}", best_ip, port)
                    };
                    println!(
                        "\n📱 [Single-Subnet Web QR] Primary Wi-Fi Direct URL (Port {}):",
                        port
                    );
                    println!("👉 Direct URL: {}", url);
                    if let Some(qr_art) = render_qr_terminal(&url) {
                        println!("\n{}", qr_art);
                    }
                }

                if candidates.len() > 1 {
                    println!("💡 Multi-Subnet Notice: This device is connected to {} candidate network interfaces.", candidates.len());
                    println!("   If the scanning device is on a different subnet/dock, use these direct URLs:");
                    for (i, c) in candidates.iter().enumerate().skip(1) {
                        let u = if c.contains(':') {
                            format!("http://[{}]:{}", c, port)
                        } else {
                            format!("http://{}:{}", c, port)
                        };
                        println!("   [{}] Subnet candidate: {}", i + 1, u);
                    }

                    let clean_name = device_meta
                        .hostname
                        .as_deref()
                        .unwrap_or("node")
                        .replace(' ', "%20");
                    let pair_payload = format!(
                        "luciola://pair?name={}&port={}&addrs={}",
                        clean_name,
                        port,
                        candidates.join(",")
                    );
                    println!("\n⚡ [Multi-Subnet Universal QR] (For Apps: dials all subnets in parallel via Happy Eyeballs):");
                    println!("👉 Universal Pairing URI: {}", pair_payload);
                    if let Some(qr_art) = render_qr_terminal(&pair_payload) {
                        println!("\n{}", qr_art);
                    }
                }
            }

            println!("\n[3] Advertised Overlay Addresses (Including VPN/tunnels):");
            let advertised = NetworkDetector::advertised_addresses();
            for a in advertised {
                println!("  🌐 {}", a);
            }
            println!("========================================================");
        }
        Commands::Forward { action } => match action {
            ForwardCommands::Serve {
                tunnel_port,
                seed,
                pin_peer,
                allow,
            } => forward_serve(tunnel_port, &seed, &pin_peer, allow).await?,
            ForwardCommands::Dial {
                listen,
                connect,
                target,
                seed,
                pin_peer,
            } => forward_dial(listen, &connect, &target, &seed, &pin_peer).await?,
            ForwardCommands::Pin { seed } => {
                let id = luciola::trust::identity_from_seed(&parse_seed(&seed)?);
                println!("public_key={}", encode_hex(&id.public_key));
                println!("fingerprint={}", id.fingerprint);
                println!("short_pin={}", id.short_pin);
            }
        },
    }

    Ok(())
}

#[cfg(unix)]
async fn run_agent(socket_path: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    println!("🛰️  [Agent] listening on {socket_path} (UDP :{port} owned machine-wide)");

    let profile = luciola::proto::Profile {
        node_id: format!("agent_{:x}", rand::random::<u32>()),
        name: luciola_net::DeviceDetector::detect()
            .hostname
            .unwrap_or_else(|| "Desktop".into()),
        profile_rev: 1,
        addresses: NetworkDetector::local_candidate_addresses(),
        udp_port: port,
        tcp_port: 0,
        device: Some(luciola_net::DeviceDetector::detect()),
        device_id: None,
        product: Some("luciola-agent".into()),
        extra: None,
        public_key: None,
    };
    let config = DiscoveryConfig {
        self_profile: profile,
        listen_port: port,
        broadcast_port: port,
        ..Default::default()
    };

    let engine = DiscoveryEngine::bind(config).await?;
    let mut events = engine.subscribe();
    engine.clone().spawn();
    engine.announce().await;

    // Fanout: every connected product client receives every engine event.
    let (tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let tx_pump = tx.clone();
    tokio::spawn(async move {
        loop {
            let line = match events.recv().await {
                Ok(PeerEvent::Found(p)) => format!(
                    r#"{{"type":"found","nodeId":"{}","name":"{}","ip":"{}","udpPort":{}}}"#,
                    p.node_id, p.name, p.ip, p.udp_port
                ),
                Ok(PeerEvent::Updated(p)) => format!(
                    r#"{{"type":"updated","nodeId":"{}","name":"{}","ip":"{}"}}"#,
                    p.node_id, p.name, p.ip
                ),
                Ok(PeerEvent::Lost(id)) => format!(r#"{{"type":"lost","nodeId":"{id}"}}"#),
                Err(_) => continue,
            };
            let _ = tx_pump.send(line);
        }
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let rx = tx.subscribe();
        let engine = engine.clone();
        tokio::spawn(handle_agent_client(stream, rx, engine));
    }
}

#[cfg(unix)]
async fn handle_agent_client(
    stream: UnixStream,
    mut rx: tokio::sync::broadcast::Receiver<String>,
    engine: std::sync::Arc<DiscoveryEngine>,
) {
    let (reader, mut writer) = stream.into_split();
    let _ = writer
        .write_all(b"{\"type\":\"hello\",\"product\":\"luciola-agent\"}\n")
        .await;
    // Late joiners get the current peer table first: Found events fired
    // before this client connected are gone (broadcast fanout).
    for p in engine.online_peers().await {
        let _ = writer
            .write_all(
                format!(
                    r#"{{"type":"found","nodeId":"{}","name":"{}","ip":"{}","udpPort":{}}}"#,
                    p.node_id, p.name, p.ip, p.udp_port
                )
                .as_bytes(),
            )
            .await;
        let _ = writer.write_all(b"\n").await;
    }
    let mut lines = BufReader::new(reader).lines();
    loop {
        tokio::select! {
            line = rx.recv() => {
                if let Ok(l) = line {
                    if writer.write_all(l.as_bytes()).await.is_err() || writer.write_all(b"
        ").await.is_err() {
                        break;
                    }
                }
            }
            cmd = lines.next_line() => {
                match cmd {
                    Ok(Some(text)) => {
                        let t = text.trim();
                        if t == "ping"
                            && writer.write_all(b"{\"type\":\"pong\"}\n").await.is_err() { break; }
                        // unknown commands are ignored; the event stream continues
                    }
                    _ => break,
                }
            }
        }
    }
}

#[cfg(not(unix))]
async fn run_agent(_socket_path: &str, _port: u16) -> Result<(), Box<dyn std::error::Error>> {
    Err("the discovery agent requires unix domain sockets (unix platforms only)".into())
}

// =========================== T2 端口隧道（the tunnel plan r4 §2.3） ===========================

/// hex 解码（CLI 不引入额外依赖的最小实现）。
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err(format!("hex 必须是偶数长度的 ASCII：{s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// hex 编码（`forward pin` 与启动行输出）。
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 身份种子（hex → 32 字节）。握手端 `SigningKey::from_bytes` 只收 32 字节，提前给出清晰报错。
fn parse_seed(hex: &str) -> Result<[u8; 32], String> {
    let v = decode_hex(hex).map_err(|e| format!("bad --seed: {e}"))?;
    <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| format!("--seed 必须是 32 字节，实际 {} 字节", v.len()))
}

/// 对端 pin = **公钥原文 32 字节 hex**（配对交换的 `public_key`，或 `forward pin` 输出）。
/// **pin 缺省 = 拒绝连接（deny-by-default，无 TOFU）**。
///
/// 注意：配对 URI 的 `fp=sha256:<hex>` 是公钥的 SHA-256 **摘要**，不可反推——
/// 误传摘要不会被悄悄当公钥用（握手必失败且难懂），这里显式拒绝并给替代路径。
fn parse_pin(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if let Some(digest) = s.strip_prefix("sha256:") {
        return Err(format!(
            "sha256:{digest} 是公钥的摘要指纹，无法反推公钥；--pin-peer 需要公钥原文 hex（对端执行 luciola-cli forward pin --seed <其种子> 得到 public_key，或取配对交换的 public_key）"
        ));
    }
    let v = decode_hex(s).map_err(|e| format!("bad --pin-peer: {e}"))?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
        format!(
            "--pin-peer 必须是 32 字节公钥原文 hex，实际 {} 字节",
            v.len()
        )
    })
}

/// `host:port`（IPv6 支持 `[::1]:port`）→ (host, port)。
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let err = || format!("地址必须是 host:port 形式：{s}");
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").ok_or_else(err)?;
        let port: u16 = p.parse().map_err(|_| err())?;
        return Ok((h.to_string(), port));
    }
    let (h, p) = s.rsplit_once(':').ok_or_else(err)?;
    let port: u16 = p.parse().map_err(|_| err())?;
    Ok((h.to_string(), port))
}

/// `IP:PORT` → [DialTarget]（§1.2 合法性在解析阶段即检查）。
fn parse_target(s: &str) -> Result<DialTarget, String> {
    let (host, port) = parse_host_port(s)?;
    let ip: IpAddr = host.parse().map_err(|_| format!("非法 IP：{s}"))?;
    let t = DialTarget::new(ip, port);
    if !t.validate() {
        return Err(format!("非法目标（port=0 / 未指定 / 组播 / 广播）：{s}"));
    }
    Ok(t)
}

/// T2 responder 侧（r4 §2.3 链路引导契约）：
/// `bind_dual_stack_listener` + `accept_secure(pin 必填)`，随后进入监督循环 ——
/// 会话结束（或握手被拒）后回到 accept，等待下一条链路；Ctrl+C 优雅退出。
/// 监听失败打印 `forward_bind_failed` 并 `exit != 0`。
async fn forward_serve(
    tunnel_port: u16,
    seed_hex: &str,
    pin_peer: &str,
    allow: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = parse_seed(seed_hex)?;
    let pin = parse_pin(pin_peer)?;
    let rules = allow
        .iter()
        .map(|s| ForwardRule::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("非法 --allow 规则：{e}"))?;
    let acl = ForwardAcl::new(rules);

    let listener = match bind_dual_stack_listener(tunnel_port).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("forward_bind_failed: {e}");
            std::process::exit(1);
        }
    };
    // 本端公钥公示：对端把它填进自己的 --pin-peer（改种子后须同步）。
    let local_pub = encode_hex(&luciola::trust::identity_from_seed(&seed).public_key);
    println!(
        "forward_serving tunnel_port={} local_pub={} allow={:?}",
        listener.local_addr()?.port(),
        local_pub,
        allow
    );

    let mut backoff = Duration::from_millis(500);
    loop {
        let accepted = tokio::select! {
            r = accept_secure(&listener, &seed, Some(&pin)) => r,
            _ = tokio::signal::ctrl_c() => {
                println!("forward_stopped");
                return Ok(());
            }
        };
        match accepted {
            Ok(stream) => {
                backoff = Duration::from_millis(500);
                let session = Arc::new(MuxSession::start(
                    stream,
                    Role::Responder,
                    MuxConfig::default(),
                ));
                let endpoint = start_forward_endpoint(session.clone(), acl.clone())?;
                println!("link_up mux_session_ready");
                let reason = tokio::select! {
                    r = session.wait_closed() => Some(r),
                    _ = tokio::signal::ctrl_c() => None,
                };
                let st = endpoint.status();
                endpoint.stop().await;
                match reason {
                    None => {
                        session.shutdown();
                        println!("forward_stopped status={st:?}");
                        return Ok(());
                    }
                    Some(r) => println!(
                        "link_closed reason={r} peer_close={} status={st:?} → accept next",
                        session.peer_closed()
                    ),
                }
            }
            Err(e) => {
                // 握手失败（扫描器 / pin 不符）：退避，避免成为廉价旋转入口。
                println!("handshake_failed: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
}

/// T2 initiator 侧：本地 127.0.0.1 转发 + 链路监督。
///
/// 按 §2.2 `peer_close` 语义分流：
/// - 对端**主动 CLOSE(ch 0)** → 计划内关闭 → **优雅退出**（e2e 验收：会话断开后客户端 CLI 优雅退出）；
/// - **传输层断开**（peer_close=false）→ **退避重建**：链路 → MuxSession → forward 规则整链重建
///   （r4 §2.3「CLI 侧监督」，与 T3 同语义）。
async fn forward_dial(
    listen: u16,
    connect: &str,
    target: &str,
    seed_hex: &str,
    pin_peer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, tunnel_port) = parse_host_port(connect)?;
    let target = parse_target(target)?;
    let seed = parse_seed(seed_hex)?;
    let pin = parse_pin(pin_peer)?;
    let addrs = vec![host];
    println!("local_pub={}", encode_hex(&luciola::trust::identity_from_seed(&seed).public_key));

    let mut backoff = Duration::from_millis(500);
    loop {
        match connect_secure_raced(addrs.clone(), tunnel_port, &seed, &pin).await {
            Ok(stream) => {
                backoff = Duration::from_millis(500);
                let session = Arc::new(MuxSession::start(
                    stream,
                    Role::Initiator,
                    MuxConfig::default(),
                ));
                let guard = match start_local_forward(
                    session.clone(),
                    LocalForwardConfig {
                        listen_port: listen,
                        target,
                    },
                ) {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("forward_bind_failed: {e}");
                        std::process::exit(1);
                    }
                };
                println!("forward_ready listen={} target={target}", guard.local_addr());

                let peer_closed = tokio::select! {
                    _ = session.wait_closed() => session.peer_closed(),
                    _ = tokio::signal::ctrl_c() => {
                        session.shutdown();
                        guard.stop().await;
                        println!("forward_stopped");
                        return Ok(());
                    }
                };
                let st = guard.status();
                guard.stop().await;
                if peer_closed {
                    // 对端计划内关闭 → 优雅退出，不重建。
                    println!("link_closed_by_peer → graceful exit status={st:?}");
                    return Ok(());
                }
                println!("link_lost → rebuild in {backoff:?} status={st:?}");
            }
            Err(e) => {
                println!("link_failed: {e} → retry in {backoff:?}");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
