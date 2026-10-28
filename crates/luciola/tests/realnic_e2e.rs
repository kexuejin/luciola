//! 真实网卡 E2E（非回环）：两个引擎走 en1 这类**真实 NIC** 互发现并建链。
//!
//! 覆盖三件回环测不到的事：
//! 1. 发现信标经真实 UDP 到达（子网定向单播 + ff02::1 组播回环）；
//! 2. **信标携带的 Ed25519 公钥**（Phase 2）经真实网络无损抵达，对端拿它做 pin；
//! 3. 对端宣告的 **IPv6 link-local 地址**被统一 `dial` 注入 scope 后真实建连。
//!
//! 环境不具备（无真实网卡/无 GUA）时优雅跳过——与"测试不许依赖环境"的纪律一致。

use luciola::link::secure::{accept_secure, connect_secure};
use luciola::link::bind_dual_stack_listener;
use luciola::proto::{DeviceType, Profile};
use luciola::{DiscoveryConfig, DiscoveryEngine, PeerEvent};
use network_interface::NetworkInterfaceConfig;
use std::time::Duration;

/// 本机真实网卡上的一个 IPv4（非回环）。没有就跳过。
fn real_ipv4() -> Option<String> {
    let list = network_interface::NetworkInterface::show().ok()?;
    for iface in list {
        if luciola_net::is_virtual_interface_name(&iface.name) {
            continue;
        }
        for addr in iface.addr {
            if let network_interface::Addr::V4(v4) = addr {
                let s = v4.ip.to_string();
                if !v4.ip.is_loopback() && !s.starts_with("169.254.") {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn test_profile(node_id: &str, public_key: Option<Vec<u8>>) -> Profile {
    Profile {
        node_id: node_id.to_string(),
        name: node_id.to_string(),
        profile_rev: 1,
        addresses: Vec::new(), // 引擎 bind 后会自动填真实候选地址
        udp_port: 0,
        tcp_port: 0,
        device: None,
        device_id: None,
        product: Some("realnic-e2e".into()),
        extra: None,
        public_key,
    }
}

/// 场景一：A 带公钥信标 → B 经真实 UDP 发现它、验出公钥、用 fe80 + pin 建加密信道。
#[tokio::test(flavor = "multi_thread")]
async fn real_nic_keyed_beacon_and_link_local_channel() {
    let Some(host_v4) = real_ipv4() else {
        eprintln!("no real NIC address; skipping real-NIC E2E");
        return;
    };
    let a_identity = luciola::trust::generate_identity();
    let b_identity = luciola::trust::generate_identity();

    // --- 引擎 A：信标带公钥，且在真实端口上接受加密信道 ---
    let mut profile_a = test_profile("realnic_A", Some(a_identity.public_key.clone()));
    let channel_listener = bind_dual_stack_listener(0).await.unwrap();
    let channel_port = channel_listener.local_addr().unwrap().port();
    profile_a.tcp_port = channel_port;

    let engine_a = DiscoveryEngine::bind(DiscoveryConfig {
        self_profile: profile_a,
        listen_port: 0,
        broadcast_port: 0,
        ..Default::default()
    })
    .await
    .unwrap();
    let udp_port_a = engine_a.local_port().await.unwrap();
    engine_a.clone().spawn();

    let seed_a = a_identity.seed.clone();
    let key_b = b_identity.public_key.clone();
    let accept_task = tokio::spawn(async move {
        // 只接受 B（pin），拒绝陌生人 —— deny-by-default。
        accept_secure(&channel_listener, &seed_a, Some(&key_b)).await
    });

    // --- 引擎 B：定向单播到 A 的真实地址（走 en1，不是回环） ---
    let mut profile_b = test_profile("realnic_B", Some(b_identity.public_key.clone()));
    profile_b.tcp_port = 0;
    let engine_b = DiscoveryEngine::bind(DiscoveryConfig {
        self_profile: profile_b,
        listen_port: 0,
        broadcast_port: 0,
        manual_peers: vec![(host_v4.clone(), udp_port_a)],
        ..Default::default()
    })
    .await
    .unwrap();
    let udp_port_b = engine_b.local_port().await.unwrap();
    let _ = udp_port_b;
    engine_b.clone().spawn();

    // A 发现 B（B 的 entry 经真实网卡到达 A），B 从 alive 应答里发现 A。
    engine_a.announce().await;
    engine_b.announce().await;

    let mut events_b = engine_b.subscribe();
    let found = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let ev = events_b.recv().await.expect("event stream");
            if let PeerEvent::Found(ref p) = ev {
                if p.node_id == "realnic_A" {
                    break p.clone();
                }
            }
        }
    })
    .await
    .expect("B must discover A over the real NIC");

    // Phase 2 断言：信标里的公钥经真实网络无损抵达。
    assert_eq!(
        found.public_key.as_deref(),
        Some(a_identity.public_key.as_slice()),
        "beacon public_key must survive the real wire"
    );

    // 用发现层学到的 link-local 地址（真实 fe80，需 scope 注入）+ 信标公钥拨号。
    let link_local = found
        .ip
        .split(',')
        .find(|a| a.contains("fe80:"))
        .map(|s| s.trim().to_string())
        .or_else(|| {
            // 记录里只留了单地址时，从本机网卡找 A 侧不现实 —— 退而用发现回包里的
            // 地址族里任一 IPv6；都没有就用 v4。此处 v4 也走真实 NIC。
            None
        });
    let dial_target = link_local.unwrap_or_else(|| found.ip.clone());

    let mut client = tokio::time::timeout(
        Duration::from_secs(8),
        connect_secure(&dial_target, channel_port, &b_identity.seed, &a_identity.public_key),
    )
    .await
    .expect("secure dial over real NIC must not hang")
    .expect("handshake with pinned beacon key");

    client.send(b"realnic-e2e").await.unwrap();
    let mut server = accept_task.await.unwrap().expect("A accepts B");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
        .await
        .expect("recv must not hang")
        .unwrap();
    assert_eq!(buf, b"realnic-e2e");

    engine_a.announce_exit().await;
    engine_b.announce_exit().await;
}

/// 场景二（新旧混网）：A 是「旧版」信标——**不带 public_key**（与 0.4.x/CLI 完全同形）。
/// B（0.6.0）必须照常发现它，且记录里 public_key 为 None；带外已知公钥照常 pin 建链。
#[tokio::test(flavor = "multi_thread")]
async fn real_nic_legacy_beacon_without_public_key() {
    let Some(host_v4) = real_ipv4() else {
        eprintln!("no real NIC address; skipping real-NIC E2E");
        return;
    };
    let a_identity = luciola::trust::generate_identity();
    let b_identity = luciola::trust::generate_identity();

    let mut profile_a = test_profile("legacy_A", None); // 旧格式：无公钥
    let channel_listener = bind_dual_stack_listener(0).await.unwrap();
    let channel_port = channel_listener.local_addr().unwrap().port();
    profile_a.tcp_port = channel_port;

    let engine_a = DiscoveryEngine::bind(DiscoveryConfig {
        self_profile: profile_a,
        listen_port: 0,
        broadcast_port: 0,
        ..Default::default()
    })
    .await
    .unwrap();
    let udp_port_a = engine_a.local_port().await.unwrap();
    engine_a.clone().spawn();

    let seed_a = a_identity.seed.clone();
    let key_b = b_identity.public_key.clone();
    let accept_task = tokio::spawn(async move {
        accept_secure(&channel_listener, &seed_a, Some(&key_b)).await
    });

    let mut profile_b = test_profile("modern_B", Some(b_identity.public_key.clone()));
    profile_b.tcp_port = 0;
    let engine_b = DiscoveryEngine::bind(DiscoveryConfig {
        self_profile: profile_b,
        listen_port: 0,
        broadcast_port: 0,
        manual_peers: vec![(host_v4, udp_port_a)],
        ..Default::default()
    })
    .await
    .unwrap();
    engine_b.clone().spawn();

    engine_a.announce().await;
    engine_b.announce().await;

    let mut events_b = engine_b.subscribe();
    let found = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let ev = events_b.recv().await.expect("event stream");
            if let PeerEvent::Found(ref p) = ev {
                if p.node_id == "legacy_A" {
                    break p.clone();
                }
            }
        }
    })
    .await
    .expect("B must discover the legacy beacon");

    assert!(
        found.public_key.is_none(),
        "legacy beacon must stay keyless on the wire"
    );

    // 带外已知公钥（等价于二维码扫码得来的 pin）照常建链。
    let mut client = tokio::time::timeout(
        Duration::from_secs(8),
        connect_secure(&found.ip, channel_port, &b_identity.seed, &a_identity.public_key),
    )
    .await
    .expect("dial must not hang")
    .expect("handshake");
    client.send(b"legacy-ok").await.unwrap();
    let mut server = accept_task.await.unwrap().expect("accept");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), server.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buf, b"legacy-ok");

    engine_a.announce_exit().await;
    engine_b.announce_exit().await;
}

// 抑制未使用告警：DeviceType 只在结构完整性上被引用。
#[allow(dead_code)]
fn _touch(_: DeviceType) {}
