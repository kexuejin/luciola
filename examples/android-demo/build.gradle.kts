// AGP version is governed by the machine-wide fleet config (~/.gradle/fleet/agp-version.txt);
// keep this in sync with it. AGP 9 provides built-in Kotlin — no separate
// org.jetbrains.kotlin.android plugin is allowed.
plugins {
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.20" apply false
    id("org.jetbrains.kotlin.multiplatform") version "2.2.20" apply false
    id("com.android.kotlin.multiplatform.library") version "9.4.1" apply false
}
