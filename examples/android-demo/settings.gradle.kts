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
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/central")
        google()
        mavenCentral()
    }
}

rootProject.name = "luciola-android-demo"
include(":app")
include(":luciola-kmp")
project(":luciola-kmp").projectDir = file("../../bindings/luciola-kmp")
