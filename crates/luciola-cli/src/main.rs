use clap::{Parser, Subcommand};
use luciola_core::{DiscoveryConfig, DiscoveryEngine, PeerEvent};
use luciola_net::NetworkDetector;
use luciola_proto::Profile;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

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
    },
    /// Inspect local network interfaces, TUN detection, and candidate IPs
    Ip,
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
                                println!("✨ [FOUND] Node: {} ({}) @ {}:{}", peer.name, peer.node_id, peer.ip, peer.udp_port);
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
        Commands::Beacon { name, port } => {
            let node_id = format!("luciola_{:x}", rand::random::<u32>());
            println!("📢 Broadcasting beacon as '{}' ({}) on port {}...", name, node_id, port);

            let profile = Profile {
                node_id: node_id.clone(),
                name,
                profile_rev: 1,
                addresses: NetworkDetector::local_candidate_addresses(),
                udp_port: port,
                tcp_port: port + 1,
            };

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
        Commands::Ip => {
            println!("========================================================");
            println!("       Luciola Network Interface & Route Intelligence    ");
            println!("========================================================");

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
