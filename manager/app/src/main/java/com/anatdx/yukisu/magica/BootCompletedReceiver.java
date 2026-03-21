package com.anatdx.yukisu.magica;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootCompletedReceiver extends BroadcastReceiver {
    public static final String ACTION_LAUNCH = "com.anatdx.yukisu.magica.LAUNCH";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }

        final String action = intent.getAction();
        if (!Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !ACTION_LAUNCH.equals(action)) {
            return;
        }

        MagicaHelper.launch(context, action);
    }
}
