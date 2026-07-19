package com.anatdx.yukisu.update

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import com.anatdx.yukisu.BuildConfig
import com.anatdx.yukisu.ksuApp
import com.anatdx.yukisu.ui.util.KsuCli
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.CacheControl
import okhttp3.Request
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Date
import java.util.zip.ZipInputStream

data class CiRun(
    val runId: Long,
)

data class PreparedCiUpdate(
    val apk: File,
    val signature: File,
)

sealed interface CiInstallResult {
    data object RootInstalled : CiInstallResult
    data object SystemInstallerStarted : CiInstallResult
}

object CiUpdateManager {
    private const val RUNS_API =
        "https://api.github.com/repos/Anatdx/YukiSU/actions/workflows/build-manager.yml/runs" +
            "?branch=main&status=success&per_page=1&exclude_pull_requests=true"
    private const val NIGHTLY_URL =
        "https://nightly.link/Anatdx/YukiSU/workflows/build-manager/main/Manager-arm64-v8a.zip"
    private const val APK_NAME = "app-release.apk"
    private const val SIGNATURE_NAME = "app-release.sig"
    private const val CI_RUN_ID_META_DATA = "com.anatdx.yukisu.CI_RUN_ID"
    private const val PRIMARY_KEY_FINGERPRINT = "71B2B58C2A543472BE0DA0D8F580A2CEEF67DC98"
    // Extend this set only when a new CI signing subkey is intentionally approved.
    private val ALLOWED_SIGNING_SUBKEY_FINGERPRINTS = setOf(
        "C09CE484EEA3F2D88E9CDCC8EBDB0D663D7AB2F6",
    )

    private const val MAX_ARCHIVE_BYTES = 300L * 1024 * 1024
    private const val MAX_APK_BYTES = 250L * 1024 * 1024
    private const val MAX_SIGNATURE_BYTES = 256L * 1024

    suspend fun latestSuccessfulMainRun(): CiRun? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(RUNS_API)
            .cacheControl(CacheControl.FORCE_NETWORK)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .build()

        ksuApp.okhttpClient.newCall(request).execute().use { response ->
            check(response.isSuccessful) {
                "GitHub API returned HTTP ${response.code}"
            }
            val body = response.body?.string() ?: error("GitHub API returned an empty response")
            val runs = JSONObject(body).getJSONArray("workflow_runs")
            if (runs.length() == 0) return@withContext null

            val run = runs.getJSONObject(0)
            check(run.optString("head_branch") == "main") { "GitHub returned a non-main CI run" }
            check(run.optString("event") in setOf("push", "workflow_dispatch")) {
                "GitHub returned an unsupported CI event"
            }
            check(run.optString("conclusion") == "success") { "GitHub returned an unsuccessful CI run" }
            CiRun(
                runId = run.getLong("id"),
            )
        }
    }

    suspend fun downloadAndExtract(
        context: Context,
        onProgress: (Int) -> Unit,
    ): PreparedCiUpdate = withContext(Dispatchers.IO) {
        val updateDir = File(context.cacheDir, "ci-update").apply {
            check(isDirectory || mkdirs()) { "Cannot create the CI update cache" }
        }
        val archive = File(updateDir, "Manager-arm64-v8a.zip")
        val apk = File(updateDir, APK_NAME)
        val signature = File(updateDir, SIGNATURE_NAME)
        archive.delete()
        apk.delete()
        signature.delete()

        val request = Request.Builder().url(NIGHTLY_URL).cacheControl(CacheControl.FORCE_NETWORK).build()
        ksuApp.okhttpClient.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "nightly.link returned HTTP ${response.code}" }
            val body = response.body ?: error("nightly.link returned an empty response")
            val contentLength = body.contentLength()
            check(contentLength < 0 || contentLength <= MAX_ARCHIVE_BYTES) {
                "CI artifact is too large"
            }
            body.byteStream().use { input ->
                archive.outputStream().buffered().use { output ->
                    copyDownloadWithProgress(
                        input = input,
                        output = output,
                        contentLength = contentLength,
                        onProgress = onProgress,
                    )
                }
            }
        }

        try {
            extractExpectedFiles(archive, apk, signature)
        } finally {
            archive.delete()
        }
        PreparedCiUpdate(apk, signature)
    }

    fun verify(context: Context, run: CiRun, update: PreparedCiUpdate) {
        verifyDetachedSignature(context, update.apk, update.signature)
        verifyApk(context, run, update.apk)
    }

    suspend fun install(context: Context, apk: File): CiInstallResult = withContext(Dispatchers.IO) {
        if (KsuCli.SHELL.isRoot) {
            val temporaryApk = File("/data/local/tmp", "yukisu-ci-update-${Process.myPid()}.apk")
            val source = shellQuote(apk.absolutePath)
            val target = shellQuote(temporaryApk.absolutePath)
            val command =
                "cp $source $target && chmod 0644 $target && pm install -r $target; " +
                    "result=\$?; rm -f $target; exit \$result"
            val result = KsuCli.SHELL.newJob().add(command).exec()
            check(result.isSuccess) {
                (result.err + result.out).joinToString("\n").ifBlank { "Root package install failed" }
            }
            apk.delete()
            updateSignatureSibling(apk).delete()
            CiInstallResult.RootInstalled
        } else {
            withContext(Dispatchers.Main) {
                val uri = FileProvider.getUriForFile(
                    context,
                    "${context.packageName}.fileprovider",
                    apk,
                )
                val intent = Intent(Intent.ACTION_VIEW)
                    .setDataAndType(uri, "application/vnd.android.package-archive")
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            }
            CiInstallResult.SystemInstallerStarted
        }
    }

    private fun extractExpectedFiles(archive: File, apk: File, signature: File) {
        val expected = mapOf(APK_NAME to (apk to MAX_APK_BYTES), SIGNATURE_NAME to (signature to MAX_SIGNATURE_BYTES))
        val extracted = mutableSetOf<String>()
        ZipInputStream(BufferedInputStream(FileInputStream(archive))).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.isDirectory) {
                    zip.closeEntry()
                    continue
                }
                val normalizedName = entry.name.removePrefix("./")
                check(entry.name == normalizedName || entry.name == "./$normalizedName") {
                    "Unsafe path in CI artifact"
                }
                val target = expected[normalizedName]
                    ?: error("Unexpected file in CI artifact: ${entry.name}")
                check('/' !in normalizedName && '\\' !in normalizedName) { "Unsafe path in CI artifact" }
                check(extracted.add(normalizedName)) { "Duplicate file in CI artifact: $normalizedName" }
                check(entry.size < 0 || entry.size <= target.second) { "$normalizedName is too large" }
                target.first.outputStream().buffered().use { output ->
                    copyWithLimit(zip, output, target.second)
                }
                check(target.first.length() > 0) { "$normalizedName is empty" }
                zip.closeEntry()
            }
        }
        check(extracted == expected.keys) { "CI artifact does not contain the expected APK/signature pair" }
    }

    private fun verifyDetachedSignature(context: Context, apk: File, signatureFile: File) {
        val keyRings = context.assets.open("ci-update-public-key.asc").use { keyInput ->
            PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(keyInput),
                BcKeyFingerprintCalculator(),
            )
        }
        val signature = readDetachedSignature(signatureFile)
        val signingKey = keyRings.getPublicKey(signature.keyID)
            ?: error("PGP signature was made by an unknown key")

        val owningRing = keyRings.keyRings.asSequence().firstOrNull { ring ->
            ring.getPublicKey(signingKey.keyID) != null
        } ?: error("PGP signing key is not in the embedded keyring")
        check(fingerprint(owningRing.publicKey) == PRIMARY_KEY_FINGERPRINT) {
            "PGP signing key does not belong to the pinned primary key"
        }
        check(!signingKey.isMasterKey) { "The CI artifact must be signed by an allowed subkey" }
        check(fingerprint(signingKey) in ALLOWED_SIGNING_SUBKEY_FINGERPRINTS) {
            "PGP signing subkey is not allowed"
        }
        check(!signingKey.hasRevocation()) { "PGP signing subkey is revoked" }
        check(signature.signatureType == PGPSignature.BINARY_DOCUMENT) {
            "PGP signature has an unexpected type"
        }
        checkSignatureTime(signingKey, signature.creationTime)

        signature.init(
            BcPGPContentVerifierBuilderProvider(),
            signingKey,
        )
        apk.inputStream().buffered().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                signature.update(buffer, 0, count)
            }
        }
        check(signature.verify()) { "PGP signature verification failed" }
    }

    private fun readDetachedSignature(file: File): PGPSignature {
        PGPUtil.getDecoderStream(file.inputStream().buffered()).use { decoded ->
            return findSignature(PGPObjectFactory(decoded, BcKeyFingerprintCalculator()))
                ?: error("Detached PGP signature is missing")
        }
    }

    private fun findSignature(factory: PGPObjectFactory): PGPSignature? {
        while (true) {
            when (val item = factory.nextObject() ?: return null) {
                is PGPSignatureList -> {
                    check(item.size() == 1) { "Expected exactly one detached PGP signature" }
                    return item[0]
                }
                is PGPCompressedData -> {
                    val nested = PGPObjectFactory(item.dataStream, BcKeyFingerprintCalculator())
                    findSignature(nested)?.let { return it }
                }
            }
        }
    }

    private fun checkSignatureTime(key: PGPPublicKey, signatureTime: Date) {
        check(!signatureTime.before(key.creationTime)) { "PGP signature predates its signing key" }
        val validSeconds = key.validSeconds
        if (validSeconds > 0) {
            val expiresAt = key.creationTime.time + validSeconds * 1000L
            check(signatureTime.time <= expiresAt) { "PGP signature was made after the key expired" }
        }
        check(signatureTime.time <= System.currentTimeMillis() + 10L * 60 * 1000) {
            "PGP signature time is in the future"
        }
    }

    @Suppress("DEPRECATION")
    private fun verifyApk(context: Context, requestedRun: CiRun, apk: File) {
        val packageManager = context.packageManager
        val archiveInfo = getPackageInfo(packageManager, apk.absolutePath)
            ?: error("Android rejected the APK signature or manifest")
        check(archiveInfo.packageName == context.packageName) { "APK package name does not match" }

        val currentInfo = getPackageInfo(packageManager, context.packageName)
            ?: error("Cannot read the installed package")
        val newVersion = PackageInfoCompat.getLongVersionCode(archiveInfo)
        val currentVersion = PackageInfoCompat.getLongVersionCode(currentInfo)
        check(newVersion > currentVersion) {
            "APK version $newVersion is not newer than installed version $currentVersion"
        }

        val apkRunId = archiveInfo.applicationInfo?.metaData
            ?.getString(CI_RUN_ID_META_DATA)
            ?.removePrefix("run-")
            ?.toLongOrNull()
            ?: error("APK does not contain a valid CI run ID")
        check(apkRunId >= requestedRun.runId && apkRunId > BuildConfig.CI_RUN_ID) {
            "APK CI run ID $apkRunId is not the requested update"
        }

        val archiveSigners = currentSigners(archiveInfo)
        val installedSigners = currentSigners(currentInfo)
        check(archiveSigners.isNotEmpty()) { "APK does not have an Android signing certificate" }
        check(archiveSigners == installedSigners) {
            "APK Android signing certificate does not match the installed app"
        }
    }

    @Suppress("DEPRECATION")
    private fun getPackageInfo(packageManager: PackageManager, packageNameOrPath: String): PackageInfo? {
        val flags = PackageManager.GET_META_DATA or if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        return if (File(packageNameOrPath).isFile) {
            packageManager.getPackageArchiveInfo(packageNameOrPath, flags)
        } else {
            packageManager.getPackageInfo(packageNameOrPath, flags)
        }
    }

    @Suppress("DEPRECATION")
    private fun currentSigners(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners.orEmpty()
        } else {
            info.signatures.orEmpty()
        }
        return signatures.mapTo(mutableSetOf()) { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).toHex()
        }
    }

    private fun copyWithLimit(
        input: InputStream,
        output: java.io.OutputStream,
        limit: Long,
    ) {
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            check(total <= limit) { "Downloaded file exceeds its size limit" }
            output.write(buffer, 0, count)
        }
    }

    private suspend fun copyDownloadWithProgress(
        input: InputStream,
        output: java.io.OutputStream,
        contentLength: Long,
        onProgress: (Int) -> Unit,
    ) {
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        var lastProgress = -1
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            check(total <= MAX_ARCHIVE_BYTES) { "Downloaded file exceeds its size limit" }
            output.write(buffer, 0, count)
            if (contentLength > 0) {
                val progress = ((total * 100L) / contentLength).toInt().coerceIn(0, 100)
                if (progress != lastProgress) {
                    lastProgress = progress
                    withContext(Dispatchers.Main) { onProgress(progress) }
                }
            }
        }
    }

    private fun fingerprint(key: PGPPublicKey): String = key.fingerprint.toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun updateSignatureSibling(apk: File): File = File(apk.parentFile, SIGNATURE_NAME)
}
