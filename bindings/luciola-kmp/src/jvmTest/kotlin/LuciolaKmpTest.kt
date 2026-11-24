package uniffi.luciola_uniffi

import io.github.kexuejin.luciola.LuciolaHubEvent
import io.github.kexuejin.luciola.LuciolaTransferEvent
import io.github.kexuejin.luciola.luciolaConnectWithPolicy
import io.github.kexuejin.luciola.luciolaObserveHubFlow
import io.github.kexuejin.luciola.luciolaTransferRecvLanFlow
import io.github.kexuejin.luciola.luciolaTransferSendLanFlow
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class LuciolaKmpTest {
    @Test
    fun testKotlinBindingApi() {
        // Test that functions can be called cleanly in Kotlin
        val isVirt = isVirtualNic("utun5")
        assertTrue(isVirt, "utun5 should be recognized as virtual NIC")

        val isTun = isTunVirtualIp("198.18.0.1")
        assertTrue(isTun, "198.18.0.1 should be recognized as TUN benchmark IP")

        val qr = renderQrAscii("http://192.168.2.82:8080")
        assertNotNull(qr, "Terminal QR code should be generated")

        val meta = getDeviceMeta()
        assertNotNull(meta.os)
        assertNotNull(meta.arch)
    }

    @Test
    fun testWanHelpersAndTransferCancelHandle() {
        val handle = TransferCancelHandle()
        assertFalse(handle.isCancelled())
        handle.cancel()
        assertTrue(handle.isCancelled())
        handle.close()

        val idA = identityFromSeed(ByteArray(32) { 0x11 })
        val idB = identityFromSeed(ByteArray(32) { 0x22 })
        val psk = "shared-secret-psk".toByteArray()
        val epoch = wanCurrentEpoch()
        assertTrue(epoch > 0uL)
        val roomAB = wanDeriveRoomId(idA.publicKey, idB.publicKey, psk, epoch)
        val roomBA = wanDeriveRoomId(idB.publicKey, idA.publicKey, psk, epoch)
        assertEquals(roomAB, roomBA, "room ID must be symmetric across peers")
        assertTrue(roomAB.isNotEmpty())
    }

    @Test
    fun testLanFileTransferRoundtripOverJna() {
        val seedSend = ByteArray(32) { 0x41 }
        val seedRecv = ByteArray(32) { 0x42 }
        val idSend = identityFromSeed(seedSend)
        val idRecv = identityFromSeed(seedRecv)

        val tmpDir = Files.createTempDirectory("luciola-kmp-xfer")
        val srcFile = tmpDir.resolve("sample.bin")
        val outDir = Files.createDirectories(tmpDir.resolve("out"))
        val payload = ByteArray(64 * 1024) { ((it * 17) and 0xff).toByte() }
        Files.write(srcFile, payload)

        val freePort = ServerSocket(0).use { it.localPort }.toUShort()
        val recvReceiptRef = AtomicReference<TransferReceiptDto?>()
        val recvErrRef = AtomicReference<Throwable?>()
        val recvDone = CountDownLatch(1)

        thread(name = "kmp-transfer-recv") {
            try {
                val receipt = transferRecvLan(
                    seedRecv,
                    freePort,
                    idSend.publicKey,
                    outDir.toAbsolutePath().toString(),
                    null,
                    null,
                )
                recvReceiptRef.set(receipt)
            } catch (t: Throwable) {
                recvErrRef.set(t)
            } finally {
                recvDone.countDown()
            }
        }

        // Give the listener a brief moment to bind.
        Thread.sleep(150)

        var lastAcked = 0uL
        val listener = object : TransferListener {
            override fun onProgress(progress: TransferProgressDto) {
                lastAcked = progress.bytesDone
            }
        }
        val sendReceipt = transferSendLan(
            seedSend,
            listOf("127.0.0.1"),
            freePort,
            idRecv.publicKey,
            srcFile.toAbsolutePath().toString(),
            listener,
            null,
        )

        assertTrue(recvDone.await(15, TimeUnit.SECONDS), "receiver must complete within 15s")
        assertEquals(null, recvErrRef.get(), "receiver error: ${recvErrRef.get()}")
        val recvReceipt = assertNotNull(recvReceiptRef.get())

        assertEquals(payload.size.toULong(), sendReceipt.totalBytes)
        assertEquals(payload.size.toULong(), recvReceipt.totalBytes)
        assertEquals(payload.size.toULong(), lastAcked)
        assertTrue(recvReceipt.sha256Hex.length == 64)
        assertTrue(Files.readAllBytes(outDir.resolve("sample.bin")).contentEquals(payload))

        tmpDir.toFile().deleteRecursively()
    }

    @Test
    fun testCoroutineTransferFlowAndCancellation(): Unit = runBlocking {
        val seedSend = ByteArray(32) { 0x51 }
        val seedRecv = ByteArray(32) { 0x52 }
        val idSend = identityFromSeed(seedSend)
        val idRecv = identityFromSeed(seedRecv)

        val tmpDir = Files.createTempDirectory("luciola-kmp-flow-xfer")
        val srcFile = tmpDir.resolve("flow.bin")
        val outDir = Files.createDirectories(tmpDir.resolve("out"))
        val payload = ByteArray(128 * 1024) { ((it * 31) and 0xff).toByte() }
        Files.write(srcFile, payload)

        val port = ServerSocket(0).use { it.localPort }
        val recvDeferred = async {
            luciolaTransferRecvLanFlow(
                identitySeed = seedRecv,
                listenPort = port,
                acceptPeerPublicKey = idSend.publicKey,
                destDir = outDir.toAbsolutePath().toString(),
            ).toList()
        }
        delay(150)

        val sendEvents = luciolaTransferSendLanFlow(
            identitySeed = seedSend,
            addresses = listOf("127.0.0.1"),
            port = port,
            pinnedPeerPublicKey = idRecv.publicKey,
            filePath = srcFile.toAbsolutePath().toString(),
        ).toList()
        val recvEvents = withTimeout(15_000) { recvDeferred.await() }

        assertTrue(sendEvents.any { it is LuciolaTransferEvent.Progress })
        assertTrue(recvEvents.any { it is LuciolaTransferEvent.Progress })
        val sendCompleted = sendEvents.last() as LuciolaTransferEvent.Completed
        val recvCompleted = recvEvents.last() as LuciolaTransferEvent.Completed
        assertEquals(sendCompleted.receipt.sha256Hex, recvCompleted.receipt.sha256Hex)

        // Verify coroutine cancellation aborts a blocking transferRecvLan call promptly.
        val idlePort = ServerSocket(0).use { it.localPort }
        val job = launch {
            luciolaTransferRecvLanFlow(
                identitySeed = seedRecv,
                listenPort = idlePort,
                acceptPeerPublicKey = idSend.publicKey,
                destDir = outDir.toAbsolutePath().toString(),
            ).toList()
        }
        delay(120)
        withTimeout(3_000) {
            job.cancelAndJoin()
        }
        assertTrue(job.isCancelled)

        tmpDir.toFile().deleteRecursively()
        Unit
    }

    @Test
    fun testCoroutineSecureHubAndConnectWithPolicy(): Unit = runBlocking {
        val hubSeed = ByteArray(32) { 0x61 }
        val aliceSeed = ByteArray(32) { 0x62 }
        val bobSeed = ByteArray(32) { 0x63 }
        val hubId = identityFromSeed(hubSeed)
        val aliceId = identityFromSeed(aliceSeed)
        val bobId = identityFromSeed(bobSeed)

        val startedHub = CompletableDeferred<SecureHub>()
        val gotMessage = CompletableDeferred<LuciolaHubEvent.Message>()
        val gotRejected = CompletableDeferred<LuciolaHubEvent.PeerRejected>()

        val hubJob = launch {
            luciolaObserveHubFlow(
                port = 0,
                identitySeed = hubSeed,
                allowedPeerPublicKeys = listOf(aliceId.publicKey),
            ).collect { ev ->
                when (ev) {
                    is LuciolaHubEvent.Started -> startedHub.complete(ev.hub)
                    is LuciolaHubEvent.Message -> gotMessage.complete(ev)
                    is LuciolaHubEvent.PeerRejected -> gotRejected.complete(ev)
                    else -> {}
                }
            }
        }

        val hub = withTimeout(5_000) { startedHub.await() }
        val port = hub.localPort()
        assertTrue(port > 0u)

        // Unallowed bob is rejected pre-sign.
        assertFailsWith<WanFfiException> {
            luciolaConnectWithPolicy(
                policy = RoutePolicyKind.LAN_ONLY,
                lan = LanDialConfigDto(
                    addresses = listOf("127.0.0.1"),
                    port = port,
                    identitySeed = bobSeed,
                    peerPublicKey = hubId.publicKey,
                ),
            )
        }
        withTimeout(5_000) { gotRejected.await() }

        // Allow bob dynamically, then connect alice via LAN_THEN_WAN and send message.
        assertTrue(hub.addAllowedPeer(bobId.publicKey))
        val chAlice = luciolaConnectWithPolicy(
            policy = RoutePolicyKind.LAN_THEN_WAN,
            lanBudgetMs = 1_500L,
            lan = LanDialConfigDto(
                addresses = listOf("127.0.0.1"),
                port = port,
                identitySeed = aliceSeed,
                peerPublicKey = hubId.publicKey,
            ),
            wan = null,
        )
        assertEquals(WanChannelKind.LAN_DIRECT, chAlice.channelType())

        val replyLatch = CountDownLatch(1)
        val replyRef = AtomicReference<ByteArray?>()
        val sessAlice = SecureSession(aliceSeed)
        sessAlice.attachWanChannel(
            chAlice,
            object : SecureSessionListener {
                override fun onState(state: String, detail: String?) {}
                override fun onMessage(message: ByteArray, peerFingerprint: String, remoteAddr: String?) {
                    replyRef.set(message)
                    replyLatch.countDown()
                }
            },
        )
        assertTrue(sessAlice.send("hello-from-kmp".encodeToByteArray()))
        val msg = withTimeout(5_000) { gotMessage.await() }
        assertEquals(aliceId.fingerprint, msg.fingerprint)
        assertEquals("hello-from-kmp", msg.payload.decodeToString())

        assertTrue(hub.sendTo(aliceId.fingerprint, "ack-from-hub".encodeToByteArray()))
        assertTrue(replyLatch.await(5, TimeUnit.SECONDS))
        assertEquals("ack-from-hub", replyRef.get()!!.decodeToString())

        sessAlice.disconnect()
        sessAlice.close()
        withTimeout(3_000) { hubJob.cancelAndJoin() }
    }
}
