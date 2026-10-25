package com.kapp.luciola.demo

import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.github.kexuejin.luciola.AndroidDiscoveryController
import io.github.kexuejin.luciola.PeerUiModel
import io.github.kexuejin.luciola.luciolaDeviceMeta
import io.github.kexuejin.luciola.luciolaLocalCandidates
import io.github.kexuejin.luciola.luciolaParsePairingUri
import io.github.kexuejin.luciola.luciolaRaceConnect
import io.github.kexuejin.luciola.luciolaSubnetBroadcasts
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "LuciolaRadar"
private val DISCOVERY_PORT: UShort = 17878u
private val TAG_AMBER = Color(0xFFF59E0B)
private val TAG_EMERALD = Color(0xFF10B981)
private const val WATCHDOG_INTERVAL_MS = 15_000L
private const val WATCHDOG_IDLE_MS = 45_000L
private const val WATCHDOG_MAX_CONSECUTIVE = 3

private val Bg = Color(0xFF0A0A0A)
private val CardBg = Color(0xFF171717)
private val CardBorder = Color(0xFF262626)

data class ChannelUi(
    val addr: String,
    val label: String,
    var status: String = "READY", // READY | DIALING | WON | CANCELLED | TIMEOUT
    var rttMs: Double? = null,
)

data class PairPayload(
    val name: String,
    val port: Int,
    val addrs: List<String>,
    val fingerprint: String? = null,
    val pin: String? = null,
)

/** Canonical parsing via the luciola core (pairing payload spec v2). */
fun parsePairUri(uri: String): PairPayload? {
    val p = luciolaParsePairingUri(uri) ?: return null
    return PairPayload(p.name, p.port, p.addrs, p.fingerprint, p.pin)
}

class MainActivity : ComponentActivity() {

    private val mainHandler = Handler(Looper.getMainLooper())
    private var controller: AndroidDiscoveryController? = null
    private var engineOn = mutableStateOf(false)

    // Live peer table, maintained by the KMP supervision core.
    private val peers = mutableStateListOf<PeerUiModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val ownMeta = luciolaDeviceMeta()
        val ownCandidates = luciolaLocalCandidates()
        val ownBroadcasts = luciolaSubnetBroadcasts()
        startEngine()

        setContent {
            LuciolaTheme {
                // targetSdk 35+ forces edge-to-edge: pad for the status bar and
                // gesture nav so the app top bar never sits under system UI.
                Surface(
                    modifier = Modifier
                        .fillMaxSize()
                        .systemBarsPadding(),
                    color = Bg,
                ) {
                    RadarApp(
                        ownName = Build.MODEL ?: "Android",
                        ownOs = ownMeta.os,
                        ownCandidates = ownCandidates,
                        ownBroadcasts = ownBroadcasts,
                        peers = peers,
                        engineOn = engineOn.value,
                    )
                }
            }
        }
    }

    /**
     * All supervision (MulticastLock, network watcher, watchdog, debounced
     * engine rebuilds) lives in the KMP library — the app just starts it and
     * renders peer updates.
     */
    private fun startEngine() {
        try {
            val name = Build.MODEL ?: "Android Peer"
            val c = AndroidDiscoveryController(
                context = this,
                sessionName = name,
                discoveryPort = DISCOVERY_PORT,
                product = "luciola-radar-demo",
                onPeersChanged = { list ->
                    peers.clear()
                    peers.addAll(list)
                },
            )
            c.start()
            controller?.close()
            controller = c
            engineOn.value = true
            Log.i(TAG, "engine started as $name on :$DISCOVERY_PORT (nodeId=${c.nodeId})")
        } catch (e: Exception) {
            Log.e(TAG, "engine start failed", e)
            engineOn.value = false
        }
    }

    override fun onDestroy() {
        controller?.close()
        controller = null
        super.onDestroy()
    }
}

@Composable
private fun LuciolaTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = TAG_AMBER,
            secondary = TAG_EMERALD,
            background = Bg,
            surface = CardBg,
        ),
        content = content,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RadarApp(
    ownName: String,
    ownOs: String,
    ownCandidates: List<String>,
    ownBroadcasts: List<String>,
    peers: List<PeerUiModel>,
    engineOn: Boolean,
) {
    var tab by remember { mutableIntStateOf(0) }
    val parsedPayload = remember { mutableStateOf<PairPayload?>(null) }
    val channels = remember { mutableStateListOf<ChannelUi>() }
    var raceStatus by remember { mutableStateOf("STANDBY") }
    var raceResult by remember { mutableStateOf<String?>(null) }
    var racing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@rememberLauncherForActivityResult
        val payload = parsePairUri(text)
        if (payload == null) {
            raceStatus = "INVALID"
            raceResult = "无法识别的二维码: $text"
        } else {
            parsedPayload.value = payload
            channels.clear()
            heChannels(payload.addrs).forEach { channels.add(it) }
            raceStatus = "SCANNED"
            raceResult = "已解析 ${payload.name} · ${payload.addrs.size} 个候选地址, 端口 ${payload.port}"
        }
    }

    fun beginRace() {
        val payload = parsedPayload.value ?: return
        racing = true
        raceResult = null
        raceStatus = "RACING (${channels.size}x)"
        scope.launch {
            val winner = happyEyeballsRace(channels, payload.port)
            racing = false
            if (winner != null) {
                raceStatus = "CONNECTED"
                raceResult = "✅ ${winner.label} ${winner.addr} 胜出 · RTT ${"%.1f".format(winner.rttMs ?: 0.0)}ms"
            } else {
                raceStatus = "FAILED"
                raceResult = "⚠️ 所有通道均不可达 (端口 ${payload.port})"
            }
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Top bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(CardBg)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .background(TAG_AMBER.copy(alpha = 0.12f), RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center,
            ) { Text("✨", fontSize = 16.sp) }
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Luciola KMP", fontWeight = FontWeight.Bold, fontSize = 15.sp, color = Color.White)
                Text(
                    "$ownName ($ownOs)",
                    fontSize = 11.sp,
                    color = Color(0xFF8A8A8A),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (tab == 0) {
                Button(
                    onClick = {
                        raceStatus = "STANDBY"
                        raceResult = null
                        parsedPayload.value = null
                        channels.clear()
                        tab = 1
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = TAG_AMBER),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                ) { Text("📷 扫码", fontSize = 12.sp) }
            }
        }

        // Engine status strip
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .background(if (engineOn) TAG_EMERALD else Color(0xFFEF4444), CircleShape),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                if (engineOn) "UDP 发现引擎在线 :$DISCOVERY_PORT · ${peers.size} 台在线" else "引擎启动失败",
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                color = if (engineOn) TAG_EMERALD else Color(0xFFEF4444),
            )
        }

        TabRow(
            selectedTabIndex = tab,
            containerColor = CardBg,
            contentColor = TAG_AMBER,
        ) {
            Tab(selected = tab == 0, onClick = { tab = 0 },
                text = { Text("🧭 发现", fontSize = 13.sp) })
            Tab(selected = tab == 1, onClick = { tab = 1 },
                text = { Text("📷 扫码竞速", fontSize = 13.sp) })
        }

        if (tab == 0) {
            DiscoverTab(ownCandidates, ownBroadcasts, peers)
        } else {
            ScannerTab(
                payload = parsedPayload.value,
                channels = channels,
                raceStatus = raceStatus,
                raceResult = raceResult,
                racing = racing,
                onLaunchScan = {
                    scanLauncher.launch(
                        ScanOptions().apply {
                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            setPrompt("对准电脑屏幕上的 Luciola 竞速码")
                            setBeepEnabled(false)
                            setOrientationLocked(true)
                        }
                    )
                },
                onRace = { beginRace() },
            )
        }
    }
}

@Composable
private fun DiscoverTab(candidates: List<String>, broadcasts: List<String>, peers: List<PeerUiModel>) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CardBg),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(14.dp)) {
                    InfoRow("本机候选地址", if (candidates.isEmpty()) "检测中..." else "${candidates.size} 个")
                    candidates.take(3).forEach {
                        Text("  $it", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TAG_EMERALD)
                    }
                    Spacer(Modifier.height(6.dp))
                    InfoRow("子网广播 (防 TUN)", broadcasts.joinToString(" / ").ifEmpty { "无" })
                }
            }
        }
        item {
            Text(
                "附近发现的电脑 / 节点",
                fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Color.White,
            )
        }
        if (peers.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = CardBg),
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text("📡", fontSize = 22.sp)
                        Spacer(Modifier.height(6.dp))
                        Text("正在监听局域网对等心跳...", fontSize = 12.sp, color = Color(0xFF8A8A8A))
                        Text("或点击右上角扫码与电脑配对", fontSize = 10.sp, color = Color(0xFF5A5A5A))
                    }
                }
            }
        } else {
            items(peers, key = { it.nodeId }) { p ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = CardBg),
                    shape = RoundedCornerShape(18.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, TAG_EMERALD.copy(alpha = 0.35f), RoundedCornerShape(18.dp)),
                ) {
                    Row(
                        Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(p.icon ?: "💻", fontSize = 20.sp)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(p.name, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color.White,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    p.model ?: p.deviceType ?: "node",
                                    fontSize = 9.sp,
                                    color = Color(0xFFB0B0B0),
                                    modifier = Modifier
                                        .background(Color(0xFF262626), RoundedCornerShape(5.dp))
                                        .padding(horizontal = 5.dp, vertical = 1.dp),
                                )
                            }
                            Text(
                                "${p.ip}:${p.udpPort}",
                                fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TAG_EMERALD,
                            )
                        }
                        Text("连接", fontSize = 11.sp, color = TAG_EMERALD, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}

@Composable
private fun ScannerTab(
    payload: PairPayload?,
    channels: List<ChannelUi>,
    raceStatus: String,
    raceResult: String?,
    racing: Boolean,
    onLaunchScan: () -> Unit,
    onRace: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Button(
            onClick = onLaunchScan,
            colors = ButtonDefaults.buttonColors(containerColor = TAG_AMBER),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
        ) {
            Text(if (payload == null) "📷 扫描电脑屏幕上的竞速码" else "📷 重新扫码", fontSize = 14.sp, fontWeight = FontWeight.Bold)
        }

        if (payload != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = CardBg),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("⚡ Happy Eyeballs 并发竞速通道", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = Color.White, modifier = Modifier.weight(1f))
                        Text(
                            raceStatus,
                            fontSize = 10.sp, fontFamily = FontFamily.Monospace,
                            color = when {
                                raceStatus.startsWith("CONNECTED") -> TAG_EMERALD
                                raceStatus.startsWith("RACING") -> TAG_AMBER
                                raceStatus == "FAILED" -> Color(0xFFEF4444)
                                else -> TAG_EMERALD
                            },
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    channels.forEach { ch ->
                        val (bg, border, fg) = when {
                            ch.status == "WON" -> Triple(TAG_EMERALD.copy(alpha = 0.10f), TAG_EMERALD.copy(alpha = 0.4f), TAG_EMERALD)
                            ch.status == "TIMEOUT" -> Triple(Color(0xFFEF4444).copy(alpha = 0.06f), Color(0xFFEF4444).copy(alpha = 0.3f), Color(0xFFEF4444))
                            ch.status == "CANCELLED" -> Triple(CardBg, CardBorder, Color(0xFF6A6A6A))
                            else -> Triple(Color(0xFF0F0F0F), CardBorder, Color(0xFF9A9A9A))
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp)
                                .background(bg, RoundedCornerShape(9.dp))
                                .border(1.dp, border, RoundedCornerShape(9.dp))
                                .padding(horizontal = 10.dp, vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                "• ${ch.label} ${ch.addr}",
                                fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = fg,
                                maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
                            )
                            Text(
                                when {
                                    ch.status == "WON" -> "WON (%.1fms)".format(ch.rttMs)
                                    else -> ch.status
                                },
                                fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = fg, fontWeight = if (ch.status == "WON") FontWeight.Bold else FontWeight.Normal,
                            )
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = onRace,
                        enabled = !racing,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (raceStatus.startsWith("CONNECTED")) Color(0xFF059669) else TAG_EMERALD,
                        ),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp),
                    ) {
                        Text(
                            when {
                                racing -> "⏳ 正在并发打洞竞速..."
                                raceStatus.startsWith("CONNECTED") -> "✅ 竞速对通成功！重新竞速"
                                else -> "⚡ 扫描并触发多网段竞速握手"
                            },
                            fontSize = 13.sp, fontWeight = FontWeight.Bold,
                        )
                    }
                    raceResult?.let {
                        Spacer(Modifier.height(6.dp))
                        Text(it, fontSize = 11.sp, color = Color(0xFFB0B0B0), fontFamily = FontFamily.Monospace)
                    }
                }
            }
        } else {
            Card(
                colors = CardDefaults.cardColors(containerColor = CardBg),
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(vertical = 28.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text("📷", fontSize = 24.sp)
                    Spacer(Modifier.height(6.dp))
                    Text("扫描桌面端 Web 中控台的二维码", fontSize = 12.sp, color = Color(0xFF8A8A8A))
                    Text("竞速码内置多网段候选地址, 支持跨网段直连", fontSize = 10.sp, color = Color(0xFF5A5A5A))
                }
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, fontSize = 12.sp, color = Color(0xFF9A9A9A))
        Text(value, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TAG_EMERALD)
    }
}

/** Primary 3 IPv4 + first IPv6 GUA, mirroring the desktop web demo. */
private fun heChannels(addrs: List<String>): List<ChannelUi> {
    val ipv4 = addrs.filter { !it.contains(':') }
    val ipv6 = addrs.filter { it.contains(':') }
    val list = buildList {
        ipv4.take(3).forEachIndexed { i, a ->
            add(ChannelUi(a, if (i == 0) "Wi-Fi 主网卡" else "备用网卡"))
        }
        ipv6.firstOrNull()?.let { add(ChannelUi(it, "IPv6 GUA")) }
    }
    return list.ifEmpty { listOf(ChannelUi(addrs.firstOrNull() ?: "0.0.0.0", "默认通道")) }
}

/**
 * Happy Eyeballs racing, backed by the luciola core (same implementation as
 * the web/iOS demos): dial every candidate with a stagger, first connect wins.
 * Runs on Dispatchers.IO — the engine-side call blocks.
 */
private suspend fun happyEyeballsRace(
    channels: List<ChannelUi>,
    port: Int,
): ChannelUi? {
    val outcome = withContext(Dispatchers.IO) {
        luciolaRaceConnect(channels.map { it.addr }, port)
    }
    var winner: ChannelUi? = null
    for (ui in outcome.channels) {
        val ch = channels.first { it.addr == ui.address }
        when {
            ui.won -> {
                ch.status = "WON"
                ch.rttMs = ui.rttMs
                winner = ch
            }
            ui.cancelled -> ch.status = "CANCELLED"
            else -> ch.status = "TIMEOUT"
        }
    }
    return winner
}
