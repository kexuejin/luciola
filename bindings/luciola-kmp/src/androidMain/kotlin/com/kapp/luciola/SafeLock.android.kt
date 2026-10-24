package com.kapp.luciola

internal actual class SafeLock {
    private val monitor = Any()
    actual fun <T> withLock(block: () -> T): T = synchronized(monitor) { block() }
}
