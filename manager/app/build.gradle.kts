@file:Suppress("UnstableApiUsage")

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.BuiltArtifactsLoader
import com.android.build.gradle.tasks.PackageAndroidArtifact
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File

plugins {
    alias(libs.plugins.agp.app)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.ksp)
    alias(libs.plugins.lsplugin.apksign)
    id("kotlin-parcelize")


}

@CacheableTask
abstract class CopyRenamedApkTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputApkFolder: DirectoryProperty

    @get:Internal
    abstract val builtArtifactsLoader: Property<BuiltArtifactsLoader>

    @get:OutputDirectory
    abstract val outputApkFolder: DirectoryProperty

    @get:Input
    abstract val outputFileName: Property<String>

    @TaskAction
    fun copyApk() {
        val builtArtifacts = builtArtifactsLoader.get().load(inputApkFolder.get())
            ?: error("Cannot load APK artifacts")
        val sourceApk = builtArtifacts.elements.singleOrNull()?.outputFile
            ?: error("Expected exactly one APK for ${builtArtifacts.variantName}")
        val destinationFolder = outputApkFolder.get().asFile
        check(destinationFolder.deleteRecursively()) { "Cannot clean $destinationFolder" }
        check(destinationFolder.mkdirs()) { "Cannot create $destinationFolder" }
        val destinationApk = File(destinationFolder, outputFileName.get())
        File(sourceApk).copyTo(destinationApk, overwrite = true)
    }
}

val managerVersionCode: Int by rootProject.extra
val managerVersionName: String by rootProject.extra
val ksudBundledVersion: String by rootProject.extra
val androidCmakeVersion: String by rootProject.extra

fun exposeSigningProperty(propertyName: String, envName: String) {
    if (project.findProperty(propertyName) == null) {
        val value = System.getenv(envName)?.takeIf { it.isNotBlank() } ?: return
        project.extensions.extraProperties[propertyName] = value
    }
}

exposeSigningProperty("KEYSTORE_FILE", "YUKISU_KEYSTORE")
exposeSigningProperty("KEYSTORE_PASSWORD", "YUKISU_KEYSTORE_PASSWORD")
exposeSigningProperty("KEY_ALIAS", "YUKISU_KEY_ALIAS")
exposeSigningProperty("KEY_PASSWORD", "YUKISU_KEY_PASSWORD")

apksign {
    storeFileProperty = "KEYSTORE_FILE"
    storePasswordProperty = "KEYSTORE_PASSWORD"
    keyAliasProperty = "KEY_ALIAS"
    keyPasswordProperty = "KEY_PASSWORD"
}


android {

    /**signingConfigs {
        create("Debug") {
            storeFile = file("D:\\other\\AndroidTool\\android_key\\keystore\\release-key.keystore")
            storePassword = ""
            keyAlias = ""
            keyPassword = ""
        }
    }**/
    namespace = "com.anatdx.yukisu"

    defaultConfig {
        buildConfigField("String", "KSUD_BUNDLED_VERSION", "\"$ksudBundledVersion\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            vcsInfo.include = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        /**debug {
            signingConfig = signingConfigs.named("Debug").get() as ApkSigningConfig
        }**/
    }

    buildFeatures {
        aidl = true
        buildConfig = true
        compose = true
        prefab = true
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            excludes += "lib/*/libandroidx.graphics.path.so"
        }
        resources {
            // https://stackoverflow.com/a/58956288
            // It will break Layout Inspector, but it's unused for release build.
            excludes += "META-INF/*.version"
            // https://github.com/Kotlin/kotlinx.coroutines?tab=readme-ov-file#avoiding-including-the-debug-infrastructure-in-the-resulting-apk
            excludes += "DebugProbesKt.bin"
            // https://issueantenna.com/repo/kotlin/kotlinx.coroutines/issues/3158
            excludes += "kotlin-tooling-metadata.json"
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = androidCmakeVersion
        }
    }

    // https://stackoverflow.com/a/77745844
    tasks.withType<PackageAndroidArtifact> {
        doFirst { appMetadata.asFile.orNull?.writeText("") }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    androidResources {
        generateLocaleConfig = true
    }
}

androidComponents {
    onVariants { variant ->
        val outputName =
            "YukiSU_${managerVersionName}_${managerVersionCode}-arm64-v8a-${variant.name}.apk"
        val copyTask = tasks.register<CopyRenamedApkTask>(
            "copyRenamed${variant.name.replaceFirstChar(Char::uppercaseChar)}Apk"
        ) {
            builtArtifactsLoader.set(variant.artifacts.getBuiltArtifactsLoader())
            outputApkFolder.set(
                layout.buildDirectory.dir("outputs/renamed_apk/${variant.name}")
            )
            outputFileName.set(outputName)
        }
        variant.artifacts.use(copyTask)
            .wiredWith(CopyRenamedApkTask::inputApkFolder)
            .toListenTo(SingleArtifact.APK)
    }
}

ksp {
    arg("compose-destinations.defaultTransitions", "none")
}

dependencies {
    implementation(libs.gson)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.material)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.foundation)
    implementation(libs.androidx.documentfile)
    implementation(libs.androidx.compose.foundation)

    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    implementation(libs.compose.destinations.core)
    ksp(libs.compose.destinations.ksp)

    implementation(libs.com.github.topjohnwu.libsu.core)
    implementation(libs.com.github.topjohnwu.libsu.service)
    implementation(libs.com.github.topjohnwu.libsu.io)

    implementation(libs.dev.rikka.rikkax.parcelablelist)

    implementation(libs.io.coil.kt.coil.compose)

    implementation(libs.kotlinx.coroutines.core)

    implementation(libs.me.zhanghai.android.appiconloader.coil)

    implementation(libs.sheet.compose.dialogs.core)
    implementation(libs.sheet.compose.dialogs.list)
    implementation(libs.sheet.compose.dialogs.input)

    implementation(libs.markdown)
    implementation(libs.androidx.webkit)

    implementation(libs.lsposed.cxx)

    implementation(libs.com.github.topjohnwu.libsu.core)

    implementation(libs.mmrl.platform)
    compileOnly(libs.mmrl.hidden.api)
    implementation(libs.mmrl.webui)
    implementation(libs.mmrl.ui)

    implementation(libs.accompanist.drawablepainter)

}
