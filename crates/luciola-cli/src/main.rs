use clap::{Parser, Subcommand};
use luciola::{DiscoveryConfig, DiscoveryEngine, PeerEvent};
use luciola_net::NetworkDetector;
use luciola_proto::Profile;
use qrcode::render::unicode;
use qrcode::QrCode;
use std::time::Duration;
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
    /// Inspect local network interfaces, TUN detection, and candidate IPs
    Ip {
        /// Render terminal QR code for the top local LAN IP
        #[arg(long)]
        qr: bool,
        /// Port to use in QR URL (default: 8080)
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
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
            println!("🔍 Scanning for peers on port {} (timeout: {}s)...", port, timeout_secs);
            let mut config = DiscoveryConfig::default();
            config.listen_port = 0; // Random ephemeral port to avoid conflict
            config.broadcast_port = port;

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
            println!("📢 Broadcasting beacon as '{}' ({}) on port {}...", name, node_id, port);

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

            let mut config = DiscoveryConfig::default();
            config.self_profile = profile;
            config.listen_port = port;
            config.broadcast_port = port;
            config.presence_interval = Duration::from_secs(3);

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
            println!("  {} Form Factor: {:?} ({})", device_meta.device_type.icon(), device_meta.device_type, device_meta.device_type.as_str());
            println!("  🌐 OS & Architecture: {} ({})", device_meta.os, device_meta.arch);

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
                    println!("\n📱 [Single-Subnet Web QR] Primary Wi-Fi Direct URL (Port {}):", port);
                    println!("👉 Direct URL: {}", url);
                    if let Some(qr_art) = render_qr_terminal(&url) {
                        println!("\n{}", qr_art);
                    }
                }

                if candidates.len() > 1 {
                    println!("💡 Multi-Subnet Notice: This device is connected to {} candidate network interfaces.", candidates.len());
                    println!("   If the scanning device is on a different subnet/dock, use these direct URLs:");
                    for (i, c) in candidates.iter().enumerate().skip(1) {
                        let u = if c.contains(':') { format!("http://[{}]:{}", c, port) } else { format!("http://{}:{}", c, port) };
                        println!("   [{}] Subnet candidate: {}", i + 1, u);
                    }

                    let clean_name = device_meta.hostname.as_deref().unwrap_or("node").replace(' ', "%20");
                    let pair_payload = format!("luciola://pair?name={}&port={}&addrs={}", clean_name, port, candidates.join(","));
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
    }

    Ok(())
}
