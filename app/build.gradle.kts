plugins {
    id("com.android.application") version "8.9.1"
    kotlin("android") version "2.0.21"
}

android {
    namespace = "app.netzwaechter"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.netzwaechter"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":core"))
    implementation("androidx.core:core-ktx:1.15.0")
}
