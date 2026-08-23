@file:Suppress("UnstableApiUsage")

import com.google.protobuf.gradle.id
import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationParameters
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.BuiltArtifactsLoader
import com.android.build.api.variant.ScopedArtifacts
import com.android.build.gradle.tasks.PackageAndroidArtifact
import org.gradle.api.DefaultTask
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.zip.ZipFile
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

plugins {
    alias(libs.plugins.agp.app)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.ksp)
    alias(libs.plugins.protobuf)
    id("kotlin-parcelize")


}

protobuf {
    protoc {
        artifact = libs.protobuf.protoc.get().toString()
    }
    generateProtoTasks {
        ofNonTest().forEach { task ->
            task.builtins {
                id("java") {
                    option("lite")
                }
                id("kotlin") {
                    option("lite")
                }
            }
        }
    }
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

/**
 * Works around an upstream crash in compose-ui 1.12.x:
 *
 *     java.lang.IllegalArgumentException: LayoutNode <id> not found in RectList
 *
 * `RectManager.recalculateRectIfDirty` inserts a node relative to its parent, and every
 * parent-relative RectList operation dereferences the parent's slot to read its rect
 * (`RectList.insertBasedOnParentOffset` indexes `items[parentIndex]` directly). The three
 * `parent.indexInRectList()` call sites are the only ones in RectManager that are not guarded by
 * `inRectList()`, and `LayoutNode.onReuse()` — LazyLayout item recycling — evicts a node from the
 * RectList and only re-inserts it if it is already placed. A child laid out in that window hits
 * the unguarded parent lookup and trips its `requirePrecondition`.
 *
 * The patch returns early when the parent is not tracked. `rectInParentDirty` stays true, so the
 * node is recorded on the next placement pass once the parent is back in the list.
 *
 * Present in ui 1.12.0-alpha01 through 1.13.0-alpha01. Drop this once the guard is upstream.
 */
abstract class RectListParentGuard : AsmClassVisitorFactory<InstrumentationParameters.None> {

    override fun isInstrumentable(classData: ClassData): Boolean =
        classData.className == RECT_MANAGER_NAME

    override fun createClassVisitor(
        classContext: ClassContext,
        nextClassVisitor: ClassVisitor
    ): ClassVisitor = RectManagerVisitor(nextClassVisitor)

    private class RectManagerVisitor(next: ClassVisitor) : ClassVisitor(Opcodes.ASM9, next) {

        private var patched = false

        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<out String>?
        ): MethodVisitor {
            val delegate = super.visitMethod(access, name, descriptor, signature, exceptions)
            if (name != TARGET_METHOD || descriptor != TARGET_DESC) return delegate
            patched = true
            return object : MethodVisitor(Opcodes.ASM9, delegate) {
                override fun visitCode() {
                    super.visitCode()
                    val body = Label()
                    visitVarInsn(Opcodes.ALOAD, 0)
                    visitVarInsn(Opcodes.ALOAD, 1)
                    visitMethodInsn(
                        Opcodes.INVOKESTATIC, RECT_MANAGER, GUARD_METHOD, GUARD_DESC, false
                    )
                    visitJumpInsn(Opcodes.IFEQ, body)
                    visitInsn(Opcodes.RETURN)
                    visitLabel(body)
                }
            }
        }

        override fun visitEnd() {
            check(patched) {
                "RectListParentGuard: $RECT_MANAGER_NAME has no $TARGET_METHOD$TARGET_DESC. " +
                    "compose-ui internals changed; re-check the RectList parent-lookup patch."
            }
            emitGuardMethod()
            super.visitEnd()
        }

        /**
         * `parent == null` yields false; otherwise true when the parent's cached slot is unset or
         * no longer holds the parent's id.
         */
        private fun emitGuardMethod() {
            val mv = super.visitMethod(
                Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
                GUARD_METHOD,
                GUARD_DESC,
                null,
                null
            )
            val tracked = Label()
            val untracked = Label()
            mv.visitCode()

            // LayoutNode parent = node.getParent$ui()
            mv.visitVarInsn(Opcodes.ALOAD, 1)
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL, LAYOUT_NODE, "getParent\$ui", "()$LAYOUT_NODE_DESC", false
            )
            mv.visitVarInsn(Opcodes.ASTORE, 2)
            mv.visitVarInsn(Opcodes.ALOAD, 2)
            mv.visitJumpInsn(Opcodes.IFNULL, tracked)

            // int cached = parent.getRectListIndex$ui()
            mv.visitVarInsn(Opcodes.ALOAD, 2)
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL, LAYOUT_NODE, "getRectListIndex\$ui", "()I", false
            )
            mv.visitVarInsn(Opcodes.ISTORE, 3)
            mv.visitVarInsn(Opcodes.ILOAD, 3)
            mv.visitIntInsn(Opcodes.BIPUSH, NOT_FOUND)
            mv.visitJumpInsn(Opcodes.IF_ICMPEQ, untracked)

            // manager.getRects().indexOf(parent.getSemanticsId(), cached)
            mv.visitVarInsn(Opcodes.ALOAD, 0)
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL, RECT_MANAGER, "getRects", "()$RECT_LIST_DESC", false
            )
            mv.visitVarInsn(Opcodes.ALOAD, 2)
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, LAYOUT_NODE, "getSemanticsId", "()I", false)
            mv.visitVarInsn(Opcodes.ILOAD, 3)
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, RECT_LIST, "indexOf", "(II)I", false)
            mv.visitIntInsn(Opcodes.BIPUSH, NOT_FOUND)
            mv.visitJumpInsn(Opcodes.IF_ICMPEQ, untracked)

            mv.visitLabel(tracked)
            mv.visitInsn(Opcodes.ICONST_0)
            mv.visitInsn(Opcodes.IRETURN)

            mv.visitLabel(untracked)
            mv.visitInsn(Opcodes.ICONST_1)
            mv.visitInsn(Opcodes.IRETURN)

            mv.visitMaxs(3, 4)
            mv.visitEnd()
        }
    }

    companion object {
        private const val RECT_MANAGER_NAME = "androidx.compose.ui.spatial.RectManager"
        private const val RECT_MANAGER = "androidx/compose/ui/spatial/RectManager"
        private const val RECT_LIST = "androidx/compose/ui/spatial/RectList"
        private const val LAYOUT_NODE = "androidx/compose/ui/node/LayoutNode"

        private const val LAYOUT_NODE_DESC = "L$LAYOUT_NODE;"
        private const val RECT_LIST_DESC = "L$RECT_LIST;"

        private const val TARGET_METHOD = "recalculateRectIfDirty"
        private const val TARGET_DESC = "($LAYOUT_NODE_DESC)V"

        private const val GUARD_METHOD = "yukisuIsParentUntracked"
        private const val GUARD_DESC = "(L$RECT_MANAGER;$LAYOUT_NODE_DESC)Z"

        /** `RectList.NotFound`, i.e. `-(LongsPerItem + 1)`. */
        private const val NOT_FOUND = -4
    }
}

/**
 * Fails the build when the shape [RectListParentGuard] patches no longer matches what compose-ui
 * ships, or when the patch did not make it into the merged classes. Checked against the
 * post-instrumentation class set, so a compose bump that renames, moves, or reshapes any of these
 * symbols breaks loudly instead of silently dropping the workaround.
 */
@CacheableTask
abstract class VerifyRectListPatchTask : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val classJars: ListProperty<RegularFile>

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val classDirs: ListProperty<Directory>

    @get:OutputFile
    abstract val receipt: RegularFileProperty

    @TaskAction
    fun verify() {
        val missing = mutableListOf<String>()
        val found = mutableListOf<String>()

        REQUIRED_MEMBERS.forEach { (internalName, members) ->
            val bytes = readClass(internalName)
            if (bytes == null) {
                missing += "$internalName (class not found)"
                return@forEach
            }
            val actual = methodsOf(bytes)
            members.forEach { member ->
                if (member in actual) found += "$internalName#$member"
                else missing += "$internalName#$member"
            }
        }

        // RectList.NotFound is `-(LongsPerItem + 1)`; the injected guard compares against it as a
        // literal, so a change to either constant has to fail here rather than silently disarm
        // the guard. indexOf(I)I returns NotFound on a miss.
        val rectList = readClass(RECT_LIST)
        if (rectList != null) {
            val constants = intConstantsOf(rectList, "indexOf", "(I)I")
            if (NOT_FOUND !in constants) {
                missing += "$RECT_LIST#indexOf(I)I no longer returns $NOT_FOUND " +
                    "(saw $constants); RectList.NotFound changed"
            } else {
                found += "$RECT_LIST#indexOf(I)I returns $NOT_FOUND"
            }
        }

        if (missing.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("compose-ui RectList parent-lookup patch is stale.")
                    appendLine()
                    appendLine("Missing or changed:")
                    missing.forEach { appendLine("  - $it") }
                    appendLine()
                    appendLine(
                        "This usually means compose-ui was bumped. Re-read " +
                            "androidx/compose/ui/spatial/RectManager.kt: if the unguarded " +
                            "parent.indexInRectList() calls are gone, delete " +
                            "RectListParentGuard and this task; otherwise update them to match."
                    )
                }
            )
        }

        receipt.get().asFile.apply {
            parentFile.mkdirs()
            writeText(found.joinToString(separator = "\n", postfix = "\n"))
        }
    }

    private fun readClass(internalName: String): ByteArray? {
        val entry = "$internalName.class"
        classDirs.get().forEach { dir ->
            val candidate = dir.asFile.resolve(entry)
            if (candidate.isFile) return candidate.readBytes()
        }
        classJars.get().forEach { jar ->
            ZipFile(jar.asFile).use { zip ->
                val found = zip.getEntry(entry) ?: return@use
                return zip.getInputStream(found).use { it.readBytes() }
            }
        }
        return null
    }

    private fun methodsOf(bytes: ByteArray): Set<String> {
        val methods = mutableSetOf<String>()
        ClassReader(bytes).accept(
            object : ClassVisitor(Opcodes.ASM9) {
                override fun visitMethod(
                    access: Int,
                    name: String,
                    descriptor: String,
                    signature: String?,
                    exceptions: Array<out String>?
                ): MethodVisitor? {
                    methods += name + descriptor
                    return null
                }
            },
            ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES
        )
        return methods
    }

    private fun intConstantsOf(bytes: ByteArray, name: String, descriptor: String): Set<Int> {
        val constants = mutableSetOf<Int>()
        ClassReader(bytes).accept(
            object : ClassVisitor(Opcodes.ASM9) {
                override fun visitMethod(
                    access: Int,
                    methodName: String,
                    methodDescriptor: String,
                    signature: String?,
                    exceptions: Array<out String>?
                ): MethodVisitor? {
                    if (methodName != name || methodDescriptor != descriptor) return null
                    return object : MethodVisitor(Opcodes.ASM9) {
                        override fun visitInsn(opcode: Int) {
                            if (opcode == Opcodes.ICONST_M1) constants += -1
                        }

                        override fun visitIntInsn(opcode: Int, operand: Int) {
                            if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                                constants += operand
                            }
                        }

                        override fun visitLdcInsn(value: Any?) {
                            if (value is Int) constants += value
                        }
                    }
                }
            },
            ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES
        )
        return constants
    }

    companion object {
        private const val RECT_MANAGER = "androidx/compose/ui/spatial/RectManager"
        private const val RECT_LIST = "androidx/compose/ui/spatial/RectList"
        private const val LAYOUT_NODE = "androidx/compose/ui/node/LayoutNode"

        private const val NOT_FOUND = -4

        private val REQUIRED_MEMBERS = mapOf(
            RECT_MANAGER to listOf(
                // patch site
                "recalculateRectIfDirty(L$LAYOUT_NODE;)V",
                // read by the guard
                "getRects()L$RECT_LIST;",
                // proves the instrumentation actually ran on this build
                "yukisuIsParentUntracked(L$RECT_MANAGER;L$LAYOUT_NODE;)Z",
            ),
            RECT_LIST to listOf(
                "indexOf(II)I",
                "indexOf(I)I",
            ),
            LAYOUT_NODE to listOf(
                "getParent\$ui()L$LAYOUT_NODE;",
                "getRectListIndex\$ui()I",
                "getSemanticsId()I",
            ),
        )
    }
}

val managerVersionCode = rootProject.extra["managerVersionCode"] as Int
val managerVersionName = rootProject.extra["managerVersionName"] as String
val ksudBundledVersion = rootProject.extra["ksudBundledVersion"] as String
val androidCmakeVersion = rootProject.extra["androidCmakeVersion"] as String
val ciRunId = System.getenv("GITHUB_RUN_ID")?.toLongOrNull() ?: 0L

fun signingValue(propertyName: String, environmentName: String): String? {
    return providers.gradleProperty(propertyName)
        .orElse(providers.environmentVariable(environmentName))
        .orNull
        ?.takeIf(String::isNotBlank)
}

val signingStoreFile = signingValue("KEYSTORE_FILE", "YUKISU_KEYSTORE")
val signingStorePassword = signingValue("KEYSTORE_PASSWORD", "YUKISU_KEYSTORE_PASSWORD")
val signingKeyAlias = signingValue("KEY_ALIAS", "YUKISU_KEY_ALIAS")
val signingKeyPassword = signingValue("KEY_PASSWORD", "YUKISU_KEY_PASSWORD")
val signingValues = listOf(
    signingStoreFile,
    signingStorePassword,
    signingKeyAlias,
    signingKeyPassword,
)
val hasReleaseSigning = signingValues.all { it != null }
check(signingValues.all { it == null } || hasReleaseSigning) {
    "Release signing requires KEYSTORE_FILE, KEYSTORE_PASSWORD, KEY_ALIAS, and KEY_PASSWORD"
}

android {
    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(requireNotNull(signingStoreFile))
                storePassword = requireNotNull(signingStorePassword)
                keyAlias = requireNotNull(signingKeyAlias)
                keyPassword = requireNotNull(signingKeyPassword)
            }
        }
    }
    namespace = "com.anatdx.yukisu"

    defaultConfig {
        buildConfigField("String", "KSUD_BUNDLED_VERSION", "\"$ksudBundledVersion\"")
        buildConfigField("long", "CI_RUN_ID", "${ciRunId}L")
        manifestPlaceholders["ciRunId"] = "run-$ciRunId"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            vcsInfo.include = false
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
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
            pickFirsts += "META-INF/LICENSE.md"
            // https://github.com/Kotlin/kotlinx.coroutines?tab=readme-ov-file#avoiding-including-the-debug-infrastructure-in-the-resulting-apk
            excludes += "DebugProbesKt.bin"
            // https://issueantenna.com/repo/kotlin/kotlinx.coroutines/issues/3158
            excludes += "kotlin-tooling-metadata.json"
            // Bouncy Castle bundles Picnic parameter tables and X.509 reviewer
            // messages as Java resources. CI update verification only uses
            // OpenPGP Ed25519 signatures, so none of these resources are read.
            excludes += "org/bouncycastle/pqc/legacy/picnic/lowmcL1.bin.properties"
            excludes += "org/bouncycastle/pqc/legacy/picnic/lowmcL3.bin.properties"
            excludes += "org/bouncycastle/pqc/legacy/picnic/lowmcL5.bin.properties"
            excludes += "org/bouncycastle/x509/CertPathReviewerMessages.properties"
            excludes += "org/bouncycastle/x509/CertPathReviewerMessages_de.properties"
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

    bundle {
        language {
            enableSplit = false
        }
    }
}

androidComponents {
    onVariants { variant ->
        variant.instrumentation.setAsmFramesComputationMode(
            FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_CLASSES
        )
        variant.instrumentation.transformClassesWith(
            RectListParentGuard::class.java,
            InstrumentationScope.ALL,
        ) {}

        val capitalizedVariant = variant.name.replaceFirstChar(Char::uppercaseChar)
        val verifyPatchTask = tasks.register<VerifyRectListPatchTask>(
            "verifyRectListPatch$capitalizedVariant"
        ) {
            receipt.set(
                layout.buildDirectory.file("reports/rectListPatch/${variant.name}.txt")
            )
        }
        variant.artifacts.forScope(ScopedArtifacts.Scope.ALL)
            .use(verifyPatchTask)
            .toGet(
                ScopedArtifact.CLASSES,
                VerifyRectListPatchTask::classJars,
                VerifyRectListPatchTask::classDirs,
            )
        // assemble/bundle tasks do not exist yet while variants are being configured.
        val packagingTasks = setOf("assemble$capitalizedVariant", "bundle$capitalizedVariant")
        tasks.matching { it.name in packagingTasks }.configureEach {
            dependsOn(verifyPatchTask)
        }

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

composeCompiler {
    // MMRL currently contains a method shape the optional mapping tokenizer cannot parse.
    includeComposeMappingFile = false
}

dependencies {
    implementation(libs.bouncycastle.bcpg)
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
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.exifinterface)
    implementation(libs.androidx.transition)
    implementation(libs.okhttp)
    implementation(libs.commons.compress)
    implementation(libs.xz)
    implementation(libs.protobuf.kotlin.lite)

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
    implementation(libs.ucrop)
    implementation(libs.yukifb)

    testImplementation(libs.kotlin.test)
}
