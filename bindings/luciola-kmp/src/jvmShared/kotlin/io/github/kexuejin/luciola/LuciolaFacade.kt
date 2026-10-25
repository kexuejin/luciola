package io.github.kexuejin.luciola

import uniffi.luciola_uniffi.DeviceMeta
import uniffi.luciola_uniffi.getDeviceMeta
import uniffi.luciola_uniffi.localCandidateAddresses
import uniffi.luciola_uniffi.subnetBroadcastAddresses

/**
 * Thin facade over uniffi top-level helpers so host apps consume the KMP
 * module instead of the generated bindings directly.
 */
fun luciolaDeviceMeta(): DeviceMeta = getDeviceMeta()

fun luciolaLocalCandidates(): List<String> = runCatching { localCandidateAddresses() }.getOrElse { emptyList() }

fun luciolaSubnetBroadcasts(): List<String> = runCatching { subnetBroadcastAddresses() }.getOrElse { emptyList() }

/**
 * Race TCP dials across the given addresses (Happy Eyeballs): first connect
 * wins, the rest are cancelled. BLOCKING — call from a worker dispatcher.
 */
fun luciolaRaceConnect(
    addresses: List<String>,
    port: Int,
    attemptTimeoutMs: Long = 1500,
    staggerMs: Long = 40,
): RaceOutcomeUi {
    val out = uniffi.luciola_uniffi.raceConnect(
        addresses,
        port.toUShort(),
        attemptTimeoutMs.toULong(),
        staggerMs.toULong(),
    )
    return RaceOutcomeUi(
        winner = out.winner,
        rttMs = out.rttMs,
        channels = out.channels.map {
            RaceChannelUi(
                address = it.address,
                won = it.status == uniffi.luciola_uniffi.DialStatus.WON,
                cancelled = it.status == uniffi.luciola_uniffi.DialStatus.CANCELLED,
                rttMs = it.rttMs,
            )
        },
    )
}

/** Shared selection policy: first 3 IPv4 candidates plus the first IPv6 GUA. */
fun luciolaRaceCandidates(addresses: List<String>): List<String> =
    uniffi.luciola_uniffi.defaultRaceCandidates(addresses)

/** Parse a canonical pairing URI (`luciola://pair` v1/v2 or plain http). */
fun luciolaParsePairingUri(uri: String): PairingUi? {
    val info = uniffi.luciola_uniffi.parsePairingUri(uri) ?: return null
    return PairingUi(
        name = info.name,
        product = info.product,
        port = info.port.toInt(),
        addrs = info.addrs,
        fingerprint = info.fingerprint,
        pin = info.pin,
    )
}

/** Build the canonical pairing URI. */
fun luciolaBuildPairingUri(
    name: String,
    product: String?,
    port: Int,
    addrs: List<String>,
    fingerprint: String?,
    pin: String?,
): String = uniffi.luciola_uniffi.buildPairingUri(name, product, port.toUShort(), addrs, fingerprint, pin)
