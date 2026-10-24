plugins {
    kotlin("multiplatform") version "2.1.0"
}

group = "io.github.luciola-p2p"
version = "0.1.0"

repositories {
    mavenCentral()
    google()
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "17"
        }
    }

    sourceSets {
        val commonMain by getting {
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
