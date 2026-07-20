package com.anatdx.yukisu.magica

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.File

@RequiresApi(Build.VERSION_CODES.Q)
open class AppZygotePreload : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        val ksud = File(appInfo.nativeLibraryDir, "libksud.so")
        try {
            System.loadLibrary("kernelsu")
            Log.d(TAG, "executing magica bootstrap")
            forkDontCareAndExecKsud(ksud.absolutePath)
        } catch (t: Throwable) {
            Log.e(TAG, "failed to trigger magica bootstrap", t)
        }
    }

    private companion object {
        private const val TAG = "YukiSUMagica"

        @JvmStatic
        private external fun forkDontCareAndExecKsud(ksudPath: String)
    }
}
