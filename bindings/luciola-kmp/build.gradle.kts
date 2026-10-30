plugins {
    kotlin("multiplatform") version "2.2.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.1"
    `maven-publish`
}

group = "io.github.kexuejin"
version = "0.8.2"

repositories {
    mavenCentral()
    google()
}

// ---------------------------------------------------------------------------
// Root directory holding the cross-compiled Rust artifacts per target triple.
// Never a machine-specific default. Resolution order:
//   Gradle property -> LUCIOLA_TARGET_DIR -> CARGO_TARGET_DIR
//   -> `cargo metadata` (honours [build] target-dir in ~/.cargo/config.toml)
//   -> the in-repo ./target fallback.
// ---------------------------------------------------------------------------
fun nativeRoot(propertyName: String): String {
    (findProperty(propertyName) as String?)?.let { return it }
    System.getenv("LUCIOLA_TARGET_DIR")?.let { return it }
    System.getenv("CARGO_TARGET_DIR")?.let { return it }
    val repoRoot = projectDir.parentFile.parentFile
    val fromCargo = runCatching {
        val proc = ProcessBuilder("cargo", "metadata", "--format-version", "1", "--no-deps")
            .directory(repoRoot)
            .redirectErrorStream(false)
            .start()
        val out = proc.inputStream.bufferedReader().readText()
        if (proc.waitFor() != 0) null
        else Regex("\"target_directory\":\"([^\"]+)\"").find(out)?.groupValues?.get(1)
    }.getOrNull()
    return fromCargo ?: File(repoRoot, "target").canonicalFile.absolutePath
}

kotlin {
    // Android via the AGP KMP plugin (built-in Kotlin on AGP 9; KGP androidTarget
    // is intentionally not used with AGP 9).
    androidLibrary {
        namespace = "io.github.kexuejin.luciola"
        compileSdk = 36
        // 24 rather than 26: consumer apps ship minSdk 24, and this library's
        // Android side only uses JNA + plain sockets — nothing API-26-only.
        // Declaring 26 would raise the whole app's install floor to Android 8.0.
        minSdk = 24
    }

    // Desktop JVM (tooling / future Compose Desktop demo); the uniffi Kotlin
    // bindings run on any JVM via JNA.
    jvm()

    // iOS: commonMain logic (supervision core, watchdog policy, models)
    // compiles to Kotlin/Native. Engine calls on iOS go through the Swift
    // bindings in bindings/luciola-swift, implementing DiscoveryEnginePort.
    // iOS now carries uniffi Kotlin/Native bindings too (gobley-generated,
    // cinterop against the C FFI). Static libs are cross-compiled by cargo for
    // each iOS triple; the root is resolved by nativeRoot() below and can be
    // overridden with -PiosNativeRoot.
    val iosNativeRoot = nativeRoot("iosNativeRoot")
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        val triple = if (target.name.contains("Simulator", ignoreCase = true)) {
            "aarch64-apple-ios-sim"
        } else {
            "aarch64-apple-ios"
        }
        val libDir = File(iosNativeRoot, "$triple/release")
        // 不写 `val iosMain by getting`：AGP 9 的 KMP 插件注册目标晚于默认层级模板，
        // 该源集在配置期不存在（实测 "KotlinSourceSet with name 'iosMain' not found"）。
        // 从 target 自己的 defaultSourceSet 挂目录，不依赖任何名字假设。
        target.compilations.getByName("main").defaultSourceSet.kotlin
            .srcDir(File(projectDir, "src/uniffiKmp/nativeMain/kotlin"))
        target.compilations.getByName("main").cinterops.create("luciola_uniffi") {
            defFile(File(projectDir, "src/uniffiKmp/nativeInterop/luciola_uniffi.def"))
            includeDirs(File(projectDir, "src/uniffiKmp/nativeInterop/cinterop/headers/luciola_uniffi"))
            // 注意：-libraryPath 必须走 extraOpts（给 klib 生成器），
            // 放进 compilerOpts 只会传给 clang —— 表现是
            // "Could not find 'libluciola_uniffi.a' binary in neither of []"（路径列表为空）。
            extraOpts("-libraryPath", libDir.absolutePath)
        }
        // 原生测试二进制（iosSimulatorArm64Test）是本工程第一个真正做 native
        // link 的产物（框架/xcframework 由 cargo 与 Xcode 侧链接，JVM 走 JNA），
        // 链接器需要显式拿到静态库：Undefined symbols _uniffi_... 即此因。
        target.compilations.getByName("test").compilerOptions.configure {
            freeCompilerArgs.addAll(
                "-linker-option", "-L${libDir.absolutePath}",
                "-linker-option", "-lluciola_uniffi",
            )
        }
    }

    // JVM-only sources shared by the Android and desktop compilations: the
    // generated uniffi Kotlin bindings and their thin adapter (JNA-backed).
    // gobley 生成的 KMP 绑定（可复现：scripts/generate-kmp-bindings.sh）。
    // 四份共用同一份 uniffi 元数据，只是实现方式不同
    // （JVM/Android = JNA，Native = cinterop）。
    val uniffiKmpSrc = File(projectDir, "src/uniffiKmp")
    val jvmSharedSrc = File(projectDir, "src/jvmShared/kotlin")

    sourceSets {
        val commonMain by getting {
            kotlin.srcDir(File(uniffiKmpSrc, "commonMain/kotlin"))
            // gobley 的 native 绑定用 kotlinx.atomicfu 做回调计数
            // （AtomicBoolean / compareAndSet / decrementAndGet）。
            // 只在 native 编译时才需要，但放在 commonMain 也能被 JVM 解析到。
            dependencies {
                implementation("org.jetbrains.kotlinx:atomicfu:0.26.1")
            }
        }
        val androidMain by getting {
            kotlin.srcDir(File(uniffiKmpSrc, "androidMain/kotlin"))
            kotlin.srcDir(jvmSharedSrc)
            dependencies {
                implementation("net.java.dev.jna:jna:5.14.0@aar")
                // gobley 的 android 绑定用 @RequiresApi 标注需要 26+ 的调用路径。
                implementation("androidx.annotation:annotation:1.9.1")
            }
        }
        val jvmMain by getting {
            kotlin.srcDir(File(uniffiKmpSrc, "jvmMain/kotlin"))
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
        // iOS 原生测试（§12 真实验证）：在模拟器进程里跑 cinterop 绑定与隧道 e2e。
        // ./gradlew :luciola:iosSimulatorArm64Test（需要 aarch64-apple-ios-sim 静态库）。
        // iosTest 由默认层级模板在目标注册后才存在 —— AGP 9 KMP 插件注册晚于
        // 配置期，eager getting 会报 not found（与上方 iosMain 注释同因），惰性挂。
        matching { it.name == "iosTest" }.configureEach {
            kotlin.srcDir(File(projectDir, "src/iosTest/kotlin"))
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}

// JVM 测试要能加载宿主 dylib：JNA 只按 jna.library.path 找。
// 之前这份配置不存在，jvmTest 里的绑定冒烟用例只能在"恰好能找到库"的机器上过；
// 换成 gobley 绑定后暴露成 UnsatisfiedLinkError（找不到 libluciola_uniffi.dylib）。
tasks.withType<Test>().configureEach {
    val hostLibDir = File(nativeRoot("hostNativeRoot"), "release")
    if (hostLibDir.isDirectory) {
        systemProperty("jna.library.path", hostLibDir.absolutePath)
    }
}

// 原生测试二进制链接的 libluciola_uniffi.a **不在** Gradle 的输入追踪里
//（linker 参数是不透明字符串，cinterop klib 只看头文件）。库重建后
// linkDebugTest*/linkReleaseTest* 仍判 up-to-date，测试进程会静默链到旧引擎
// —— 症状是"新 FFI 方法行为像旧 ABI"（参数错位 / junk data / 恒 false），
// 与 AGENTS.md §3 的"AAR 里旧 .so"陷阱同构。把 .a 注册为输入堵死它；
// 仍不够时对 def 文件做内容级改动强制 cinterop+link 重跑。
tasks.matching { it.name.startsWith("link") && it.name.contains("TestIos") }.configureEach {
    val root = nativeRoot("iosNativeRoot")
    inputs.files(
        File(root, "aarch64-apple-ios/release/libluciola_uniffi.a"),
        File(root, "aarch64-apple-ios-sim/release/libluciola_uniffi.a"),
    )
}

// nativeRoot() is declared with the other build helpers above the kotlin block.

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
            archiveFileName.set("luciola-${name}-${version}-javadoc.jar")
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