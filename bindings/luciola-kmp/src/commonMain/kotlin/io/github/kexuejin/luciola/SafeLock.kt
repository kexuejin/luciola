package io.github.kexuejin.luciola

/** Minimal reentrant lock abstraction so commonMain stays target-agnostic. */
internal expect class SafeLock() {
    fun <T> withLock(block: () -> T): T
}
