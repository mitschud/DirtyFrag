plugins {
    id("com.android.application")
}

android {
    namespace = "df.root"
    compileSdk = 37

    defaultConfig {
        applicationId = "df.root"
        // 31, not upstream's 32. The 32 came from upstream's initial commit and nothing here needs
        // it: nothing in the app calls an API above 31 (IpSecManager/UdpEncapsulationSocket are 28,
        // the device-protected storage context is 24, the two splash-screen theme attributes are 31,
        // and the log normaliser uses the Matcher overloads carried since the first API level - the
        // API 34 ones threw NoSuchMethodError below Android 14). So 12L-only was pure loss: it kept
        // every Android 12 phone out at install time for no reason.
        // This widens who can INSTALL, not who can root - the module table still bottoms out at
        // dfroot-android12-5.10.ko. See the Unreleased section of CHANGELOG.md.
        minSdk = 31
        targetSdk = 37
        versionCode = 34
        versionName = "1.17"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        create("keystore") {
            storeFile = file("keystore.jks")
            storePassword = "dirtyfrag"
            keyAlias = "dirtyfrag"
            keyPassword = "dirtyfrag"
        }
    }

    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("keystore")
        }
        release {
            signingConfig = signingConfigs.getByName("keystore")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

// AGP 9 removed the old applicationVariants API; this is the replacement.
androidComponents {
    onVariants { variant ->
        variant.outputs.forEach { output ->
            output.outputFileName.set("dirtyfrag.apk")
        }
    }
}
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        checkReleaseBuilds = false
    }

    buildFeatures {
        // No viewbinding: df.root.ActivityMainBinding is written by hand, which keeps
        // every binding.<id> call site and drops androidx.databinding:viewbinding.
        viewBinding = false
        // The toolbar version pill reads BuildConfig.VERSION_NAME, so the pill
        // can never fall behind versionName again.
        buildConfig = true
    }

    externalNativeBuild {
        cmake {
            path("src/main/jni/CMakeLists.txt")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    // Deliberately empty. The whole UI is framework widgets plus the custom views in
    // df.root (CardStackLayout, DraggableCardView, PillButton, OneUiSwitch,
    // TwoStepProgressView, BottomFadeView). appcompat, material, constraintlayout and
    // viewbinding used to sit here and pulled 40 androidx/material artifacts into the
    // APK; the replacements are documented under "Unreleased" in CHANGELOG.md.
}
