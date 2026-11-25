plugins {
    id("com.android.application") version "8.13.2"
    id("org.jetbrains.kotlin.android") version "2.2.21"
}

val hydratVersion = file("../../internal/appupdate/version.txt").readText().trim()
val versionParts = hydratVersion.split(".").map { it.toInt() }

android {
    namespace = "org.hydrat.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.hydrat.app"
        minSdk = 29
        targetSdk = 35
        versionCode = versionParts.fold(0) { number, part -> number * 1000 + part }
        versionName = hydratVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += "arm64-v8a" }
    }
    buildFeatures { buildConfig = true }
    buildTypes.create("qa") {
        initWith(buildTypes.getByName("debug"))
        applicationIdSuffix = ".qa"
        matchingFallbacks += "debug"
    }
    testBuildType = "qa"
    sourceSets.getByName("main") {
        jniLibs.srcDir("build/hydrat/jni")
        assets.srcDir("build/hydrat/assets")
        assets.srcDir("../../internal/i18n/catalog")
    }
    packaging.jniLibs.useLegacyPackaging = true
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { jvmToolchain(17) }

dependencies {
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
