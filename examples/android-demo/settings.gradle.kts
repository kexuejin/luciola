pluginManagement {
    repositories {
        // CN mirrors first (dl.google.com is TLS-reset on this network);
        // upstream repos kept as fallback.
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/central")
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    // PREFER_PROJECT: the included :luciola-kmp module declares its own
    // repositories so it also stays buildable standalone.
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories {
        mavenLocal()
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/central")
        google()
        mavenCentral()
    }
}

rootProject.name = "luciola-android-demo"
include(":app")
// Dev wiring: consume the library as an included project. Real consumers use
// the published artifact: implementation("io.github.kexuejin:luciola:0.3.0")
// with mavenLocal() in repositories (see bindings/luciola-kmp/README.md).
include(":luciola")
project(":luciola").projectDir = file("../../bindings/luciola-kmp")
// Dev wiring: consume the library as an included project. Real consumers use
// the published artifact: implementation("io.github.kexuejin:luciola-kmp:0.1.0")
// with mavenLocal() in repositories (see bindings/luciola-kmp/README.md).

