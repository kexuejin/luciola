pluginManagement {
    repositories {
        // CN mirrors first (dl.google.com is TLS-reset on this network);
        // upstream repos kept as fallback.
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/central")
        google()
        mavenLocal()
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
        mavenCentral()
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/central")
        google()
        mavenLocal()
        mavenCentral()
    }
}

rootProject.name = "luciola-android-demo"
include(":app")
// Dev wiring: consume the library as an included project. Released consumers
// use mavenCentral() with: implementation("io.github.kexuejin:luciola:0.8.0")
include(":luciola")
project(":luciola").projectDir = file("../../bindings/luciola-kmp")
