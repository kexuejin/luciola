package io.github.kexuejin.luciola

import platform.Foundation.NSLock

internal actual class SafeLock {
    private val nsLock = NSLock()
    actual fun <T> withLock(block: () -> T): T {
        nsLock.lock()
        return try { block() } finally { nsLock.unlock() }
    }
}
