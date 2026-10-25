plugins {
    kotlin("multiplatform") version "2.2.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.1"
    `maven-publish`
}

group = "io.github.kexuejin"
version = "0.3.0"

repositories {
    mavenCentral()
    google()
}

kotlin {
    // Android via the AGP KMP plugin (built-in Kotlin on AGP 9; KGP androidTarget
    // is intentionally not used with AGP 9).
    androidLibrary {
        namespace = "io.github.kexuejin.luciola"
        compileSdk = 36
        minSdk = 26
    }

    // Desktop JVM (tooling / future Compose Desktop demo); the uniffi Kotlin
    // bindings run on any JVM via JNA.
    jvm()

    // iOS: commonMain logic (supervision core, watchdog policy, models)
    // compiles to Kotlin/Native. Engine calls on iOS go through the Swift
    // bindings in bindings/luciola-swift, implementing DiscoveryEnginePort.
    iosArm64()
    iosSimulatorArm64()

    // JVM-only sources shared by the Android and desktop compilations: the
    // generated uniffi Kotlin bindings and their thin adapter (JNA-backed).
    val uniffiJvmSrc = File(projectDir, "src/uniffiJvm/kotlin")
    val jvmSharedSrc = File(projectDir, "src/jvmShared/kotlin")

    sourceSets {
        val androidMain by getting {
            kotlin.srcDir(uniffiJvmSrc)
            kotlin.srcDir(jvmSharedSrc)
            dependencies {
                implementation("net.java.dev.jna:jna:5.14.0@aar")
            }
        }
        val jvmMain by getting {
            kotlin.srcDir(uniffiJvmSrc)
            kotlin.srcDir(jvmSharedSrc)
            dependencies {
                implementation("net.java.dev.jna:jna:5.14.0")
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}

// The AAR must embed the Rust core; publishing without it produces a broken
// artifact. scripts/publish-maven-local.sh builds the .so before publishing.
val verifyNativeLib = tasks.register("verifyNativeLib") {
    val so = File(projectDir, "src/androidMain/jniLibs/arm64-v8a/libluciola_uniffi.so")
    doLast {
        if (!so.isFile) {
            throw GradleException(
                "Missing $so.\nBuild it first:  cargo ndk -t arm64-v8a -o bindings/luciola-kmp/src/androidMain/jniLibs build --release -p luciola-uniffi\nor just run scripts/publish-maven-local.sh"
            )
        }
    }
}
tasks.matching { it.name.startsWith("publish") }.configureEach { dependsOn(verifyNativeLib) }

publishing {
    publications.withType<MavenPublication>().configureEach {
        pom {
            name.set("luciola-kmp")
            description.set("Luciola LAN discovery engine: supervision, path racing, trust & secure channels (KMP)")
            licenses {
                license {
                    name.set("MIT")
                    url.set("https://opensource.org/licenses/MIT")
                }
            }
        }
    }
    // Local Maven publishing only for now; remote repos come later.
    repositories {
        maven {
            name = "Local"
            setUrl("${layout.buildDirectory}/repoLocal")
        }
    }
}
