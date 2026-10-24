# Luciola (萤火)

<p align="center">
  <strong>轻量、高韧性、解决真实世界网络暗坑的局域网对等发现与网卡感知引擎</strong>
</p>

<p align="center">
  <a href="#特性">特性</a> •
  <a href="#为什么需要-luciola">解决的痛点</a> •
  <a href="#快速开始">快速开始</a> •
  <a href="#多语言绑定">多语言支持</a> •
  <a href="#架构分层">架构分层</a> •
  <a href="README.md">English</a>
</p>

---

## 特性

- 🌐 **懂“国内宽带国情”的 IPv6 直连**：全面支持 RFC 4291/4193 作用域分类；内置 `/64` 前缀感知算法，能把中国电信/联通/移动分配给家庭 LAN 的全球单播 IPv6（GUA）智能识别为“局域网”，打破公网防火墙限制，实现端到端免中继直连。
- 🛡️ **彻底免疫代理 TUN 截流（Anti-TUN）**：当用户开启 Clash、Sing-box 等 TUN 增强模式时，`0.0.0.0/1` 路由会强行吸走受限广播 `255.255.255.255`。Luciola 自动为每个物理网卡计算直连定向 **Subnet Broadcast（子网广播，如 `192.168.2.255`）**，由于 `/24` 路由优先级更高，强制从物理网卡发出，彻底打破代理截流。
- 🎯 **网卡物理真实性与打分优选**：精准识别并降权 Docker、VMware、Tailscale、Radmin 以及 Windows 移动热点虚拟适配器（`192.168.137.x`），并支持 WSL2 内部穿透获取 Windows 宿主机物理 IP，保证生成的直连二维码百分之百可达。
- ⚡ **零开销对等发现协议**：轻量级 UDP 状态机（`entry` 握手、`alive` 应答、`presence` 周期心跳、`exit` 离线挥手），自带随机防风暴抖动（Jitter）与时间窗口去重。
- 🔌 **全生态一等公民多语言绑定**：Rust 核心内核，零 GC、极低内存，提供 Node.js（`@luciola/core` via N-API）、Android/JVM 及 iOS/macOS 绑定。

---

## 为什么需要 Luciola？（对比传统方案）

| 真实世界痛点 | 传统 mDNS / Bonjour | 手写正则 / ipconfig 粗糙选网卡脚本 | **Luciola (萤火)** |
| :--- | :--- | :--- | :--- |
| **企业/校园/酒店 Wi-Fi** | 组播（Multicast）被路由器强制丢弃，完全失联 | — | **子网定向广播 + 单播对账**，多网卡冗余兜底 |
| **家庭宽带 IPv6 (GUA)** | 误判为公网 WAN，安全策略误拦截 | 完全忽略 IPv6，只做 IPv4 | **`/64` 同前缀同 LAN 算法**，优先直连 |
| **Clash / Sing-box TUN 模式** | 广播包被 `0.0.0.0/1` 代理吞掉，静默失联 | 忽略 TUN 截流问题 | **定向子网广播**（直连直达物理链路） |
| **WSL2 / 虚拟网卡环境** | 暴露内部 NAT IP `172.x`，手机扫码打不开 | 极容易误挑 Docker/Tailscale 网卡 | **网卡多维正负评分 + WSL2 物理穿透** |
| **移动端 Doze 省电模式** | 后台强行杀掉 mDNS 监听 | 仅支持 PC Web | **平台生命周期感知与空闲回退** |

---

## 快速开始

### 1. 命令行 CLI 工具

```bash
# 查看本机网卡诊断、子网广播与干净候选 IP
cargo run -p luciola-cli -- ip

# 实时扫描并监听局域网对端
cargo run -p luciola-cli -- scan

# 广播本机存在（作为节点）
cargo run -p luciola-cli -- beacon --name "My Laptop"
```

### 2. 在 Node.js / Electron 中使用（替代旧版选网卡脚本）

```javascript
const { selectLanIp, subnetBroadcastAddresses } = require('@luciola/core');

// 1. 自动挑出手机最可能可达的局域网 IP（用于生成二维码）
const bestIp = selectLanIp();
console.log(`请用手机扫描直连: http://${bestIp}:3000`);

// 2. 获取防代理劫持的子网广播列表
const broadcasts = subnetBroadcastAddresses();
console.log('子网广播地址:', broadcasts);
```

### 3. Web 双端联动演示（桌面中控台 + 移动端模拟器）

```bash
cd examples/web-radar-demo
node server.js   # 打开 http://localhost:3000
```

真实 UDP 协议心跳、子网定向广播、Happy Eyeballs 多网段竞速与实时雷达，详见 [examples/web-radar-demo](examples/web-radar-demo)。

---

## 架构

```
luciola/
├── crates/
│   ├── luciola-ip/       # RFC 作用域、/64 GUA 前缀匹配、TUN 198.18 过滤 (no_std)
│   ├── luciola-net/      # 硬件网卡枚举、打分优选、WSL 穿透、子网广播计算
│   ├── luciola-proto/    # 零 IO 协议状态机、抖动防风暴调度器
│   ├── luciola-core/     # 基于 Tokio 的异步 UDP 广播自愈引擎
│   └── luciola-cli/      # 命令行雷达工具
└── bindings/
    └── luciola-node/     # Node.js 原生 N-API 模块 (@luciola/core)
```

---

## 开源许可

本项目采用双重开源许可：
- [MIT 许可证](LICENSE-MIT)
- [Apache 2.0 许可证](LICENSE-APACHE)
