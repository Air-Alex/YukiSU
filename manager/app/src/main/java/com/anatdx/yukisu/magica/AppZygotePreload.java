package com.anatdx.yukisu.magica;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.File;

public class AppZygotePreload implements ZygotePreload {
    public static final String TAG = "YukiSUMagica";

    private static native void forkDontCareAndExecKsud(String ksudPath);

    @Override
    public void doPreload(@NonNull ApplicationInfo appInfo) {
        final File ksud = new File(appInfo.nativeLibraryDir, "libksud.so");
        try {
            System.loadLibrary("kernelsu");
            Log.d(TAG, "executing magica bootstrap");
            forkDontCareAndExecKsud(ksud.getAbsolutePath());
        } catch (Throwable t) {
            Log.e(TAG, "failed to trigger magica bootstrap", t);
        }
    }
}
