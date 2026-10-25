# Luciola 产品接入手册

面向基于 luciola 构建的产品(剪贴板同步、文件传输、投屏类)的集成指南。
坐标:`io.github.kexuejin:luciola`(KMP)、`@luciola/core`(Node)。

## 1. 端口分配(同机多产品)

UDP **17878 保留给"单引擎设备"**。同机运行第二个 luciola 产品时,自选其他端口
(如 17880),每个产品一个独立 mesh。端口被占时引擎会重试 5 秒,失败后通过
`onError("bind_failed", ...)`(uniffi/KMP)或 `{type:"error"}`(Node)上报——
**UI 必须展示这个错误**,否则用户只会看到"扫描不到设备"。

Profile 携带 `deviceId`(设备分组)与 `product`(产品标签),对端 UI 应按
deviceId 折叠同一物理设备上的多个产品。

## 2. 生命周期(移动端)

- **Android**:引擎依赖 MulticastLock(库已处理)与前台存活。App 进后台后,
  cached-app freezer 会冻结整个进程——引擎、看门狗全部暂停,回前台自动恢复。
  需要"后台持续可发现/可接收"的产品**必须用前台服务**(Foreground Service +
  `FOREGROUND_SERVICE_CONNECTED_DEVICE`),并把 `AndroidDiscoveryController`
  挂在 service 的生命周期上。
- **iOS**:App 悬挂即暂停;后台发现不可行,只在前台运行。长连接需求考虑
  background task / 推送唤醒,按产品评估。
- 网络变化(VPN 开关、Wi-Fi 切换)时库自动防抖重启引擎(800ms),看门狗在
  网络可用但引擎静默 45s 时重建(最多连续 3 次)。

## 3. 信任与配对(必须做,不可选)

发现是开放的;**数据面默认只对可信设备开放**。

1. 首次启动 `generateDeviceIdentity()`,把 32 字节 seed 存入
   **Keychain(iOS)/ Keystore(Android)/ 系统钥匙串或受限文件(桌面)**——
   不要存明文 SharedPreferences。
2. 配对流程:主机侧 `buildPairingUri(name, product, port, addrs, fingerprint,
   pin)` 生成二维码(渲染用 `renderQrSvg`);手机扫码 `parsePairingUri` 解析,
   **两屏核对 6 位 pin**(不一致=中间人,中止);然后把对端公钥写入
   `TrustStore`。
3. 分级:
   - `Full`(自己的设备):允许无感推送——剪贴板同步的默认形态;
   - `Partial`:可见、每次动作弹确认——文件接收推荐;
   - 未配对:只出现在发现列表,任何数据面动作拒绝。
4. 数据通道一律走 `SecureSession/SecureChannel`:拨号方必须持对端 pinned
   公钥;监听方 TOFU 模式上报对端指纹供 pin 核对后入库。

## 4. 安全信道的使用姿势

- `connect(addresses, port, pinnedKey, autoReconnect, listener)`:多地址竞速
  (Happy Eyeballs)后直接在胜出 socket 上握手,无竞速-建连间隙。
- 断线自动重连(1s→30s 指数退避),状态回调:
  `connecting/connected/retrying/closed/error`。
- 15s 空闲发 keepalive,连续两个周期无响应判定对端死亡(应对 Wi-Fi 省电)。
- `send()` 有界队列(64 帧):返回 false = 未连接或对端卡住,退避重试,
  **不要同步自旋**。
- 监听方 `listen()` 是循环接受:一条连接关闭后自动重新等待。

## 5. 事件模型(务必全量实现)

- 发现回调四种事件:`found / updated / lost / error`。
  **`lost` 必须处理**(从 UI 移除节点),否则对端关机后永远"在线"。
- KMP:`DiscoveryController` 已内置 peer 表维护与老化,宿主只消费
  `onPeersChanged` 快照;`onEngineError` 需要透传到 UI。

## 6. 已知环境行为(排障表)

| 症状 | 原因 | 处置 |
| :--- | :--- | :--- |
| 引擎"在线"但永远扫不到 | 17878 被同机其他产品占用,bind 回落随机端口 | 换端口;`isBound()`/`bind_failed` 上报后 UI 提示 |
| 手机 App 后台"假死" | Android freezer 冻结进程 | 前台服务;回前台自动恢复 |
| 广播全部丢失、单播正常 | TUN 代理(`0.0.0.0/1`)截流受限广播 | 库已走子网定向广播,确认 `subnetBroadcastAddresses()` 非空 |
| macOS UDP 发送报 EPIPE | ICMP 错误粘滞在 socket | Rust 引擎按周期重发自愈;Node 侧裸 dgram 需重建 socket |
| 模拟器 ↔ 宿主机互相不可见 | 模拟器共享宿主网络栈,广播不回环 | 用 manualPeers 单播,或真机验证 |
| iOS 模拟器端口冲突 | 宿主其他应用占用 17878 | 换 DISCOVERY_PORT |

## 7. 协议版本

发现信封带 `v` 字段(当前 1)。旧节点发出的无版本帧按 v=1 解码,双向兼容。
协议破坏性变更会递增 `v` 并在变更日志标注。

## 8. IPv6 发现

引擎是双栈的:v4 socket(子网定向广播)之外,还有一个 IPv6-only socket
(同端口),加入每个物理网卡的 `ff02::1` 链路本地多播组,单播回复按地址族
选择出口 socket。因此:

- IPv4/IPv6 混合网:双路并行,先到先得;
- IPv6-only 环境(国内宽带 GUA 直连场景):多播发现 + GUA 单播均可达;
- `manualPeers` 直接填裸 IPv6 地址(如 `2408:8248::1`)即可。

**实测警告(ff02::1 多播的现实可靠性)**:多播依赖 AP 把组播帧转投给每个无线客户端,
很多家用路由器不转发 STA 间多播(与 mDNS 在廉价路由器上时好时坏同因)。实测中双端
均已正确入组(OS 层确认 en1/wlan0 均在 ff02::1),但一台 AP 始终不投递。因此:
多播是 v6 发现的"零配置路径",**跨网段/不可靠 AP 场景请叠加 manualPeers 单播**(引擎
同时发多播与单播,不冲突)。

## 9. 桌面 agent(同机多产品的推荐形态)

多个桌面产品共存时,不要各自抢 17878——跑一个机器级 agent,由它独占
发现端口并向本机产品分发事件:

```bash
luciola-cli agent            # 默认 unix socket: $TMPDIR/luciola-agent.sock
```

协议(行分隔 JSON):连接即收 `{"type":"hello",...}` + 当前在线节点快照
(每节点一条 `found`);之后实时推送 `found/updated/lost`;发 `ping` 得
`pong`。Node 产品用 `net.connect(sockPath)` 接入即可。

## 10. 链路诊断

`SecureChannel/SecureChannel.stats()`:`framesSent / framesReceived /
connectionsEstablished / reconnectAttempts`——驱动 UI 健康指示与排障。

## 11. 安全备注

安全信道为自研组合(标准原语,SIGMA 式),**未经外部审计**——上线携带
敏感数据前请按 `SECURITY.md` 的流程安排评审;发现帧本身不认证,Profile
字段一律当展示数据处理,信任判断只认 TrustStore + 安全信道。
