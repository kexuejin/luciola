package io.github.kexuejin.luciola

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.luciola_uniffi.HubEventListener
import uniffi.luciola_uniffi.HubPeerInfoDto
import uniffi.luciola_uniffi.LanDialConfigDto
import uniffi.luciola_uniffi.RoutePolicyKind
import uniffi.luciola_uniffi.SecureHub
import uniffi.luciola_uniffi.TransferCancelHandle
import uniffi.luciola_uniffi.TransferFfiException
import uniffi.luciola_uniffi.TransferListener
import uniffi.luciola_uniffi.TransferProgressDto
import uniffi.luciola_uniffi.TransferReceiptDto
import uniffi.luciola_uniffi.WanChannel
import uniffi.luciola_uniffi.WanConfig
import uniffi.luciola_uniffi.connectWan
import uniffi.luciola_uniffi.connectWithPolicy
import uniffi.luciola_uniffi.transferRecvLan
import uniffi.luciola_uniffi.transferRecvWan
import uniffi.luciola_uniffi.transferSendLan
import uniffi.luciola_uniffi.transferSendWan

/**
 * Establish a WAN secure channel off the UI thread.
 */
suspend fun luciolaConnectWan(
    config: WanConfig,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): WanChannel = withContext(dispatcher) {
    connectWan(config)
}

/**
 * Establish an authenticated channel according to [policy] (`LAN_ONLY`, `LAN_THEN_WAN`, `WAN_ONLY`)
 * off the UI thread. Security errors (pin mismatch / tamper) never fall back to WAN.
 */
suspend fun luciolaConnectWithPolicy(
    policy: RoutePolicyKind,
    lanBudgetMs: Long = 1_500L,
    lan: LanDialConfigDto? = null,
    wan: WanConfig? = null,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): WanChannel {
    require(lanBudgetMs >= 0L) { "lanBudgetMs must be >= 0" }
    return withContext(dispatcher) {
        connectWithPolicy(policy, lanBudgetMs.toULong(), lan, wan)
    }
}

/**
 * Progress and completion events emitted by `luciolaTransfer*Flow` helpers.
 */
sealed interface LuciolaTransferEvent {
    data class Progress(val progress: TransferProgressDto) : LuciolaTransferEvent
    data class Completed(val receipt: TransferReceiptDto) : LuciolaTransferEvent
}

private fun runTransferFlow(
    dispatcher: CoroutineDispatcher,
    block: (TransferListener, TransferCancelHandle) -> TransferReceiptDto,
): Flow<LuciolaTransferEvent> = channelFlow {
    val cancelHandle = TransferCancelHandle()
    val cancelWatcher = launch(start = CoroutineStart.UNDISPATCHED) {
        try {
            awaitCancellation()
        } finally {
            cancelHandle.cancel()
        }
    }
    try {
        val listener = object : TransferListener {
            override fun onProgress(progress: TransferProgressDto) {
                trySend(LuciolaTransferEvent.Progress(progress))
            }
        }
        val receipt = withContext(dispatcher) {
            block(listener, cancelHandle)
        }
        send(LuciolaTransferEvent.Completed(receipt))
    } catch (e: TransferFfiException.Cancelled) {
        if (currentCoroutineContext().isActive) {
            throw e
        }
        throw CancellationException("Luciola file transfer cancelled", e)
    } finally {
        withContext(NonCancellable) {
            cancelWatcher.cancelAndJoin()
        }
        cancelHandle.cancel()
        cancelHandle.close()
    }
}.buffer(Channel.BUFFERED)

/**
 * Send one file over a pin-verified LAN connection (no TOFU), streaming [LuciolaTransferEvent]s.
 * Cancelling the collecting coroutine cancels the underlying Rust transfer immediately.
 */
fun luciolaTransferSendLanFlow(
    identitySeed: ByteArray,
    addresses: List<String>,
    port: Int,
    pinnedPeerPublicKey: ByteArray,
    filePath: String,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Flow<LuciolaTransferEvent> {
    require(port in 1..65535) { "port $port out of 1..65535 range" }
    return runTransferFlow(dispatcher) { listener, cancel ->
        transferSendLan(
            identitySeed,
            addresses,
            port.toUShort(),
            pinnedPeerPublicKey,
            filePath,
            listener,
            cancel,
        )
    }
}

/**
 * Accept one pin-verified LAN file transfer into [destDir] (no TOFU), streaming [LuciolaTransferEvent]s.
 * Cancelling the collecting coroutine cancels the underlying Rust accept/transfer immediately.
 */
fun luciolaTransferRecvLanFlow(
    identitySeed: ByteArray,
    listenPort: Int,
    acceptPeerPublicKey: ByteArray,
    destDir: String,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Flow<LuciolaTransferEvent> {
    require(listenPort in 0..65535) { "listenPort $listenPort out of 0..65535 range" }
    return runTransferFlow(dispatcher) { listener, cancel ->
        transferRecvLan(
            identitySeed,
            listenPort.toUShort(),
            acceptPeerPublicKey,
            destDir,
            listener,
            cancel,
        )
    }
}

/**
 * Send one file over an already-established [WanChannel] (consumes [channel]).
 */
fun luciolaTransferSendWanFlow(
    channel: WanChannel,
    filePath: String,
    maxRelayBytes: Long? = null,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Flow<LuciolaTransferEvent> {
    require(maxRelayBytes == null || maxRelayBytes >= 0L) { "maxRelayBytes must be >= 0" }
    return runTransferFlow(dispatcher) { listener, cancel ->
        transferSendWan(
            channel,
            filePath,
            maxRelayBytes?.toULong(),
            listener,
            cancel,
        )
    }
}

/**
 * Receive one file over an already-established [WanChannel] (consumes [channel]).
 */
fun luciolaTransferRecvWanFlow(
    channel: WanChannel,
    destDir: String,
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Flow<LuciolaTransferEvent> = runTransferFlow(dispatcher) { listener, cancel ->
    transferRecvWan(
        channel,
        destDir,
        listener,
        cancel,
    )
}

/**
 * Lifecycle and message events emitted by [luciolaObserveHubFlow].
 */
sealed interface LuciolaHubEvent {
    data class Started(val hub: SecureHub) : LuciolaHubEvent
    data class PeerConnected(val peer: HubPeerInfoDto) : LuciolaHubEvent
    data class Message(
        val fingerprint: String,
        val remoteAddr: String,
        val payload: ByteArray,
    ) : LuciolaHubEvent
    data class PeerDisconnected(val fingerprint: String) : LuciolaHubEvent
    data class PeerRejected(val remoteAddr: String, val reason: String) : LuciolaHubEvent
}

/**
 * Start a multi-peer [SecureHub] and stream its events as a cold [Flow].
 * Cancelling collection stops and closes the underlying [SecureHub].
 */
fun luciolaObserveHubFlow(
    port: Int = 0,
    identitySeed: ByteArray,
    allowedPeerPublicKeys: List<ByteArray> = emptyList(),
    dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Flow<LuciolaHubEvent> {
    require(port in 0..65535) { "port $port out of 0..65535 range" }
    return callbackFlow {
        val listener = object : HubEventListener {
            override fun onPeerConnected(peer: HubPeerInfoDto) {
                trySend(LuciolaHubEvent.PeerConnected(peer))
            }

            override fun onMessage(fingerprint: String, remoteAddr: String, payload: ByteArray) {
                trySend(LuciolaHubEvent.Message(fingerprint, remoteAddr, payload))
            }

            override fun onPeerDisconnected(fingerprint: String) {
                trySend(LuciolaHubEvent.PeerDisconnected(fingerprint))
            }

            override fun onPeerRejected(remoteAddr: String, reason: String) {
                trySend(LuciolaHubEvent.PeerRejected(remoteAddr, reason))
            }
        }
        val hub = withContext(dispatcher) {
            SecureHub.start(
                port.toUShort(),
                identitySeed,
                allowedPeerPublicKeys,
                listener,
            )
        }
        trySend(LuciolaHubEvent.Started(hub))
        awaitClose {
            hub.stop()
            hub.close()
        }
    }.buffer(Channel.BUFFERED)
}
