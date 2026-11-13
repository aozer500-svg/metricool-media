pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "netzwaechter"

include(":core")

// Das Android-Modul wird nur eingebunden, wenn ein Android SDK vorhanden ist
// (Android Studio legt local.properties an). So laesst sich :core ueberall testen.
val hasAndroidSdk = file("local.properties").exists() ||
    System.getenv("ANDROID_HOME") != null ||
    System.getenv("ANDROID_SDK_ROOT") != null
if (hasAndroidSdk) {
    include(":app")
}
