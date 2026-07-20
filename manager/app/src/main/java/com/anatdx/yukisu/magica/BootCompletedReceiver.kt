package com.anatdx.yukisu.magica

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.anatdx.yukisu.ui.util.rootAvailable

open class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            action != Intent.ACTION_BOOT_COMPLETED &&
            action != ACTION_LAUNCH
        ) {
            return
        }
        if (rootAvailable()) {
            return
        }

        MagicaHelper.launch(context, action)
    }

    companion object {
        const val ACTION_LAUNCH = "com.anatdx.yukisu.magica.LAUNCH"
    }
}
