//! KMP iOS 路径的**运行时**验证（AGENTS.md §12：编进 klib ≠ 在真机/模拟器上跑过）。
//! 由 `./gradlew :luciola:iosSimulatorArm64Test` 在 iOS 模拟器进程中执行：
//! cinterop 直接调用 libluciola_uniffi.a，覆盖绑定冒烟、隧道控制面校验、
//! 经隧道的真实 TCP 回环，以及 IosNetworkMonitor 的 Network.framework 集成。

@file:OptIn(ExperimentalForeignApi::class)

package uniffi.luciola_uniffi

import io.github.kexuejin.luciola.IosNetworkMonitor
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.test.*
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/** 事件收集器：Rust 线程回调 → 互斥列表（Kotlin/Native 用 atomicfu 锁）。 */
private class Collector : SecureSessionListener {
    private val lock = SynchronizedObject()
    private val states = ArrayList<Pair<String, String?>>()
    override fun onState(state: String, detail: String?) {
        synchronized(lock) { states.add(state to detail) }
    }

    override fun onMessage(message: ByteArray, peerFingerprint: String, remoteAddr: String?) {}

    fun count(state: String): Int = synchronized(lock) { states.count { it.first == state } }

    fun snapshot(): List<Pair<String, String?>> = synchronized(lock) { states.toList() }
}

private fun awaitTrue(timeoutMs: Long, label: String, cond: () -> Boolean) {
    val start = TimeSource.Monotonic.markNow()
    while (start.elapsedNow() < timeoutMs.milliseconds) {
        if (cond()) return
        usleep(50_000u)
    }
    fail("timeout(${timeoutMs}ms): $label")
}

// ---------------------------------------------------------------- posix 小工具

/** 16 位主机序端口 → 网络序 UShort（cinterop 不透出 htons 宏，手工换序）。 */
private fun netOrder(port: Int): UShort =
    (((port and 0xff) shl 8) or ((port shr 8) and 0xff)).toUShort()

private fun sockaddr_in.fillLoopback(port: Int) {
    memset(ptr, 0, sizeOf<sockaddr_in>().toULong())
    sin_family = AF_INET.convert()
    sin_port = netOrder(port)
    sin_addr.s_addr = 0x0100007Fu // 127.0.0.1（网络字节序）
}

/** 阻塞式 TCP 连接 127.0.0.1:port，返回 fd（带 5s 接收超时）。 */
@OptIn(ExperimentalForeignApi::class)
private fun tcpConnect(port: Int): Int {
    val fd = socket(AF_INET, SOCK_STREAM, 0)
    check(fd >= 0) { "socket: errno=$errno" }
    memScoped {
        val addr = alloc<sockaddr_in>()
        addr.fillLoopback(port)
        val r = connect(fd, addr.ptr.reinterpret(), sizeOf<sockaddr_in>().convert())
        check(r == 0) { "connect(127.0.0.1:$port): errno=$errno" }
        val tv = alloc<timeval>()
        tv.tv_sec = 5
        tv.tv_usec = 0
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv.ptr, sizeOf<timeval>().convert())
    }
    return fd
}

/** 监听 127.0.0.1:0 的回环 TCP 套接字，返回 (fd, 实际端口)。 */
@OptIn(ExperimentalForeignApi::class)
private fun listenLoopback(): Pair<Int, Int> {
    val fd = socket(AF_INET, SOCK_STREAM, 0)
    check(fd >= 0) { "socket: errno=$errno" }
    memScoped {
        val addr = alloc<sockaddr_in>()
        addr.fillLoopback(0)
        check(bind(fd, addr.ptr.reinterpret(), sizeOf<sockaddr_in>().convert()) == 0) { "bind: errno=$errno" }
        check(listen(fd, 8) == 0) { "listen: errno=$errno" }
        val len = alloc<socklen_tVar>()
        len.value = sizeOf<sockaddr_in>().convert()
        val actual = alloc<sockaddr_in>()
        check(getsockname(fd, actual.ptr.reinterpret(), len.ptr) == 0) { "getsockname" }
        val p = actual.sin_port.toInt() and 0xffff
        return fd to (((p and 0xff) shl 8) or ((p shr 8) and 0xff))
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun setNonblocking(fd: Int) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) or O_NONBLOCK)
}

@OptIn(ExperimentalForeignApi::class)
private fun writeAll(fd: Int, data: ByteArray) {
    data.usePinned { pinned ->
        var off = 0
        while (off < data.size) {
            val n = send(fd, pinned.addressOf(off), (data.size - off).convert(), 0).toInt()
            check(n > 0) { "send: errno=$errno" }
            off += n
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun readExact(fd: Int, buf: ByteArray) {
    buf.usePinned { pinned ->
        var off = 0
        while (off < buf.size) {
            val n = recv(fd, pinned.addressOf(off), (buf.size - off).convert(), 0).toInt()
            check(n > 0) { "recv: errno=$errno (off=$off/${buf.size})" }
            off += n
        }
    }
}

/** 端口在 127.0.0.1 上是否空闲（bind 即关）。 */
@OptIn(ExperimentalForeignApi::class)
private fun portFree(port: Int): Boolean {
    val fd = socket(AF_INET, SOCK_STREAM, 0)
    if (fd < 0) return false
    var ok = false
    memScoped {
        val addr = alloc<sockaddr_in>()
        addr.fillLoopback(port)
        ok = bind(fd, addr.ptr.reinterpret(), sizeOf<sockaddr_in>().convert()) == 0
    }
    close(fd)
    return ok
}

/** 找一对连续空闲端口 (L, L+1)：隧道默认占 secure+1。 */
private fun freePortPair(): Int {
    val seed = TimeSource.Monotonic.markNow().elapsedNow().inWholeMilliseconds
    repeat(500) {
        val l = 20000 + ((seed * 7919 + it * 104729) % 30000).toInt()
        if (l < 65530 && portFree(l) && portFree(l + 1)) return l
    }
    fail("no free port pair")
}

private fun freePort(): Int {
    val seed = TimeSource.Monotonic.markNow().elapsedNow().inWholeMilliseconds
    repeat(500) {
        val p = 20000 + ((seed * 6271 + it * 15485863) % 30000).toInt()
        if (p < 65535 && portFree(p)) return p
    }
    fail("no free port")
}

// ---------------------------------------------------------------- 测试

/** 绑定冒烟（镜像 jvmTest）：cinterop 调用真的在模拟器进程里执行。 */
class LuciolaIosBindingSmokeTest {
    @Test
    fun bindingApiExecutesOnSimulator() {
        assertTrue(isVirtualNic("utun5"), "utun5 should be recognized as virtual NIC")
        assertTrue(isTunVirtualIp("198.18.0.1"), "198.18.0.1 should be recognized as TUN IP")
        assertNotNull(renderQrAscii("http://127.0.0.1:8080"), "QR should render")
        val meta = getDeviceMeta()
        assertNotNull(meta.os)
        assertNotNull(meta.arch)
    }
}

/** IosNetworkMonitor：Network.framework path monitor 在模拟器上的真实运行。 */
class LuciolaIosNetworkMonitorTest {
    @Test
    fun monitorStartsAndReportsUp() {
        // 构造即创建并启动真实 nw_path_monitor；update handler 的 cinterop
        // 签名若有误，baseline 派发会当场崩溃 —— 存活 1s 即为集成验证。
        val monitor = IosNetworkMonitor()
        var changes = 0
        monitor.onChange { changes += 1 }
        usleep(1_000_000u) // 1s：等 baseline 派发（签名错误会当场崩溃）
        assertTrue(monitor.isNetworkUp(), "simulator loopback path must report up")
        // 不强制 changes>0：模拟器空闲时只有 baseline（被吞掉，by design）。
        println("[ios-test] network monitor up, changes dispatched: $changes")
    }
}

/** 隧道控制面：角色/参数校验的同步失败契约在模拟器上成立。 */
class LuciolaIosTunnelControlPlaneTest {
    @Test
    fun controlPlaneValidatesSynchronously() {
        // Dial 角色、无基址：NotConfigured → 同步 false
        SecureSession(ByteArray(32) { it.toByte() }).use { dial ->
            assertFalse(
                dial.startLocalForward(0u, "127.0.0.1", 9u),
                "no base → startLocalForward must fail",
            )
            // 非法目标（纯数字串，既非 IP 也非合法主机名）→ InvalidTarget
            assertFalse(
                dial.startLocalForward(0u, "1.2.3.999", 80u),
                "numeric-ghost target must fail",
            )
            assertTrue(dial.forwardStats().isEmpty(), "no registrations → empty stats")
            dial.setTunnelKeepalive(0uL, 0uL)
            assertTrue(dial.setTunnelPort(0u), "setTunnelPort(0) resets override")
        }

        // Listen 角色：dial 侧 API 一律 RoleMismatch，空规则/非法规则 → InvalidRule
        val listenEv = Collector()
        SecureSession(ByteArray(32) { (it + 1).toByte() }).use { listen ->
            listen.listen(freePort().toUShort(), null, listenEv)
            assertFalse(
                listen.startLocalForward(0u, "127.0.0.1", 9u),
                "listen role must not start local forward",
            )
            assertFalse(listen.enableForwardEndpoint(emptyList()), "empty rules must fail")
            assertFalse(
                listen.enableForwardEndpoint(listOf(ForwardRuleDto("1.2.3.999", 1u, 2u, false))),
                "numeric-ghost rule host must fail",
            )
            awaitTrue(10_000, "error events delivered") { listenEv.count("error") >= 3 }
            val errors = listenEv.snapshot().filter { it.first == "error" }.map { it.second ?: "" }
            assertTrue(
                errors.any { it.startsWith("invalid target") } ||
                    errors.any { it.startsWith("invalid forward rule") },
                "validation errors reported: $errors",
            )
            assertTrue(
                errors.any { it.contains("listen()") },
                "role mismatch must be reported: $errors",
            )
        }
    }
}

/** 完整回环 e2e：消息链路（listen+connect）→ 隧道（secure+1）→ 本地转发 → TCP 回环。 */
class LuciolaIosTunnelE2eTest {
    @Test
    fun tunnelForwardRoundtripOnSimulator() {
        val l = freePortPair()
        val idListen = identityFromSeed(ByteArray(32) { 2 })
        val upstream = listenLoopback()
        setNonblocking(upstream.first)

        val listenEv = Collector()
        val listenCh = SecureSession(ByteArray(32) { 2 })
        listenCh.listen(l.toUShort(), null, listenEv)

        val dialEv = Collector()
        val dialCh = SecureSession(ByteArray(32) { 1 })
        dialCh.connect(listOf("127.0.0.1"), l.toUShort(), idListen.publicKey, true, dialEv)

        awaitTrue(30_000, "message link connected") { dialCh.isConnected() }

        // 两端各自注册转发/端点 → 隧道（L+1）懒建立
        assertTrue(
            listenCh.enableForwardEndpoint(listOf(ForwardRuleDto("127.0.0.1", 1u, 65535u, false))),
            "endpoint rules must be accepted: ${listenEv.snapshot()}",
        )
        assertTrue(
            dialCh.startLocalForward(0u, "127.0.0.1", upstream.second.toUShort()),
            "local forward must register",
        )

        // 等 stats 行 active，拿系统分配的实端口
        var realPort = 0
        awaitTrue(30_000, "local forward row active") {
            val row = dialCh.forwardStats().firstOrNull()
            realPort = row?.listenPort?.toInt() ?: 0
            row?.active == true && realPort != 0
        }

        // 经隧道写 → 上游 echo（非阻塞 accept 轮询）→ 读回逐字节比对
        val payload = ByteArray(4096) { (it * 31 and 0xff).toByte() }
        val client = tcpConnect(realPort)
        writeAll(client, payload)
        var upstreamConn = -1
        awaitTrue(30_000, "upstream accept") {
            upstreamConn = accept(upstream.first, null, null)
            upstreamConn >= 0
        }
        val echoed = ByteArray(payload.size)
        readExact(upstreamConn, echoed)
        writeAll(upstreamConn, echoed)
        close(upstreamConn)
        readExact(client, echoed)
        close(client)
        assertTrue(payload.contentEquals(echoed), "payload must survive the tunnel byte-for-byte")

        val row = dialCh.forwardStats().first()
        assertTrue(row.channelsTotal >= 1uL, "channelsTotal >= 1: $row")
        assertEquals(0uL, row.dialDenied, "no ACL denials expected: $row")
        assertEquals("local", row.kind, "row kind must be local")

        assertEquals(0, dialEv.count("error"), "dial errors: ${dialEv.snapshot()}")
        assertEquals(0, listenEv.count("error"), "listen errors: ${listenEv.snapshot()}")

        dialCh.disconnect()
        dialCh.close()
        listenCh.close()
        close(upstream.first)
        println("[ios-test] tunnel roundtrip OK (listen=$l local=$realPort)")
    }
}
