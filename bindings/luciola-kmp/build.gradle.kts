plugins {
    kotlin("multiplatform") version "2.2.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.1"
    `maven-publish`
}

group = "io.github.kexuejin"
version = "0.4.6"

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
        // 24 而不是 26:消费方(消费方)minSdk=24;本库的 Android 侧只用到
        // JNA + 标准 socket,没有 API 26 才有的调用。26 会让整包安装要求升到 8.0。
        minSdk = 24
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
        // Central requires a javadoc artifact per module; a per-publication
        // stub task (shared files break Gradle's implicit-dependency checks).
        val javadocJar = tasks.register("javadocJar-${name}", Jar::class) {
            archiveFileName.set("luciola-${name}-0.4.4-javadoc.jar")
            archiveClassifier.set("javadoc")
            from(resources.text.fromString("luciola KMP — see https://github.com/kexuejin/luciola"))
        }
        artifact(javadocJar.get())
        pom {
            name.set("luciola")
            description.set("Luciola LAN discovery engine: supervision, path racing, trust & secure channels (Kotlin Multiplatform)")
            url.set("https://github.com/kexuejin/luciola")
            licenses {
                license {
                    name.set("MIT")
                    url.set("https://opensource.org/licenses/MIT")
                }
                license {
                    name.set("Apache-2.0")
                    url.set("https://opensource.org/licenses/Apache-2.0")
                }
            }
            developers {
                developer {
                    id.set("kexuejin")
                    name.set("Luciola Contributors")
                }
            }
            scm {
                connection.set("scm:git:git://github.com/kexuejin/luciola.git")
                developerConnection.set("scm:git:ssh://github.com/kexuejin/luciola.git")
                url.set("https://github.com/kexuejin/luciola")
            }
        }
    }
    repositories {
        maven {
            name = "Local"
            setUrl(layout.buildDirectory.dir("repoLocal").get())
        }
        // Enable with -PcentralUrl=... -PcentralUser=... -PcentralToken=...
        // (Maven Central portal: https://central.sonatype.com -> your namespace)
        if (project.hasProperty("centralUrl")) {
            maven {
                name = "Central"
                setUrl(project.property("centralUrl") as String)
                credentials {
                    username = project.property("centralUser") as String
                    password = project.property("centralToken") as String
                }
            }
        }
    }
}


// Sign every publication when GPG key material is present (Central requirement).
// Provide via gradle properties: signingKey (armored, \n-escaped) + signingPassword,
// or a local ~/.gnupg keyring for interactive publishing.
if (project.hasProperty("signingKey") || project.hasProperty("signing.gnupg.keyName")) {
    apply(plugin = "signing")
    configure<org.gradle.plugins.signing.SigningExtension> {
        val keyValue = project.findProperty("signingKey") as String?
        if (keyValue != null) {
            useInMemoryPgpKeys(keyValue.replace("\\n", "\n"), project.findProperty("signingPassword") as String?)
        }
        sign(publishing.publications)
    }
}
