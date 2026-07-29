package com.anatdx.yukisu.update

import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import android.os.IBinder
import android.os.ParcelFileDescriptor
import com.anatdx.yukisu.ICiUpdateInstaller
import com.topjohnwu.superuser.ipc.RootService

class CiUpdateInstallerService : RootService() {
    private val installer: PackageInstaller
        get() = packageManager.packageInstaller

    private inner class InstallerStub : ICiUpdateInstaller.Stub() {
        override fun createSession(apkSize: Long, packageName: String): Int {
            require(apkSize in 1..MAX_APK_BYTES) { "Invalid CI update APK size" }
            require(packageName.isNotBlank()) { "Invalid CI update package name" }

            val params = PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL
            ).apply {
                setAppPackageName(packageName)
                setSize(apkSize)
            }
            return installer.createSession(params)
        }

        override fun writeSession(
            sessionId: Int,
            apkStream: ParcelFileDescriptor,
            apkSize: Long,
        ) {
            require(apkSize in 1..MAX_APK_BYTES) { "Invalid CI update APK size" }
            installer.openSession(sessionId).use { session ->
                ParcelFileDescriptor.AutoCloseInputStream(apkStream).use { input ->
                    session.openWrite(APK_SPLIT_NAME, 0L, apkSize).use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        var total = 0L
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            check(total <= apkSize) { "CI update APK exceeds its declared size" }
                            output.write(buffer, 0, count)
                        }
                        check(total == apkSize) {
                            "CI update APK is truncated: expected $apkSize bytes, received $total"
                        }
                        session.fsync(output)
                    }
                }
            }
        }

        override fun commitSession(sessionId: Int, statusReceiver: IntentSender) {
            installer.openSession(sessionId).use { session ->
                session.commit(statusReceiver)
            }
        }

        override fun abandonSession(sessionId: Int) {
            installer.abandonSession(sessionId)
        }
    }

    override fun onBind(intent: Intent): IBinder = InstallerStub()

    private companion object {
        const val APK_SPLIT_NAME = "base.apk"
        const val MAX_APK_BYTES = 32L * 1024 * 1024
    }
}
