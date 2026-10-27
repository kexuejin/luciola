plugins {
    kotlin("multiplatform") version "2.2.20"
    id("com.android.kotlin.multiplatform.library") version "9.4.1"
    `maven-publish`
}

group = "io.github.kexuejin"
version = "0.5.1"

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
    // iOS 现在带 uniffi 的 Kotlin/Native 绑定（gobley 生成，cinterop 调 C FFI）。
    // 静态库由 scripts/build-ios-natives.sh 交叉编译；路径可用 -PiosNativeRoot 覆盖。
    val iosNativeRoot = (findProperty("iosNativeRoot") as String?)
        ?: "target"
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
    }
}

// JVM 测试要能加载宿主 dylib：JNA 只按 jna.library.path 找。
// 之前这份配置不存在，jvmTest 里的绑定冒烟用例只能在"恰好能找到库"的机器上过；
// 换成 gobley 绑定后暴露成 UnsatisfiedLinkError（找不到 libluciola_uniffi.dylib）。
tasks.withType<Test>().configureEach {
    val hostLibDir = File(iosNativeRootForHost(), "release")
    if (hostLibDir.isDirectory) {
        systemProperty("jna.library.path", hostLibDir.absolutePath)
    }
}

fun iosNativeRootForHost(): String =
    (findProperty("hostNativeRoot") as String?) ?: "target"

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