package com.kapp.luciola

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
