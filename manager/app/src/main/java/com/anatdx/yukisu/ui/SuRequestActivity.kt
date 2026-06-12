package com.anatdx.yukisu.ui

import android.content.pm.ActivityInfo
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Build
import android.os.Bundle
import android.view.Window
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.addCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.anatdx.yukisu.R
import com.anatdx.yukisu.ui.theme.KernelSUTheme
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.roundToInt
import kotlin.concurrent.thread
import kotlinx.coroutines.delay

class SuRequestActivity : ComponentActivity() {

    private var reqId = -1
    private var nonce = 0L
    private var sockName: String? = null

    @Volatile
    private var replied = false

    enum class Choice(val wire: Int) {
        ALLOW_FOREVER(1),
        ALLOW_ONCE(2),
        DENY(3),
        DENY_HIDE(4),
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LOCKED
        window.requestFeature(Window.FEATURE_NO_TITLE)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        window.addFlags(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                window.setHideOverlayWindows(true)
            } catch (_: SecurityException) {
                // Best effort on vendor frameworks.
            }
        }
        super.onCreate(savedInstanceState)
        val screenWidth = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            windowManager.currentWindowMetrics.bounds.width()
        } else {
            @Suppress("DEPRECATION")
            resources.displayMetrics.widthPixels
        }
        setFinishOnTouchOutside(false)
        onBackPressedDispatcher.addCallback(this) { onChoice(Choice.DENY) }

        reqId = intent.getIntExtra(EXTRA_REQ_ID, -1)
        nonce = intent.getLongExtra(EXTRA_NONCE, 0L)
        sockName = intent.getStringExtra(EXTRA_SOCKET)
        val uid = intent.getIntExtra(EXTRA_UID, -1)
        val comm = intent.getStringExtra(EXTRA_COMM).orEmpty()

        if (reqId < 0 || sockName.isNullOrEmpty()) {
            finish()
            return
        }

        val pkg = runCatching {
            packageManager.getPackagesForUid(uid)?.firstOrNull()
        }.getOrNull()
        val label = pkg?.let { p ->
            runCatching {
                packageManager.getApplicationLabel(
                    packageManager.getApplicationInfo(p, 0)
                ).toString()
            }.getOrNull()
        } ?: comm.ifEmpty { uid.toString() }
        val icon: ImageBitmap? = pkg?.let { p ->
            runCatching {
                packageManager.getApplicationIcon(p).toBitmap(144, 144).asImageBitmap()
            }.getOrNull()
        }

        setContent {
            KernelSUTheme(showBackground = false) {
                Box(
                    modifier = Modifier.padding(12.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    SuRequestCard(
                        appLabel = label,
                        packageName = pkg ?: comm,
                        uid = uid,
                        icon = icon,
                        onChoice = ::onChoice,
                    )
                }
            }
        }
        window.decorView.post {
            window.setLayout(
                (screenWidth * 0.85f).roundToInt(),
                WindowManager.LayoutParams.WRAP_CONTENT,
            )
        }
    }

    private fun onChoice(choice: Choice) {
        if (replied) return
        replied = true
        val wire = choice.wire
        thread {
            reply(wire)
            runOnUiThread { finishAndRemoveTask() }
        }
    }

    override fun onDestroy() {
        // Fail closed if the window disappears without a choice.
        if (!replied && !isChangingConfigurations) {
            replied = true
            thread { reply(Choice.DENY.wire) }
        }
        super.onDestroy()
    }

    private fun reply(choice: Int) {
        val name = sockName ?: return
        runCatching {
            val socket = LocalSocket()
            try {
                socket.connect(
                    LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT)
                )
                val buf = ByteBuffer.allocate(WIRE_SIZE).order(ByteOrder.LITTLE_ENDIAN)
                buf.putInt(WIRE_MAGIC)
                buf.putInt(reqId)
                buf.putLong(nonce)
                buf.putInt(choice)
                socket.outputStream.write(buf.array())
                socket.outputStream.flush()
            } finally {
                runCatching { socket.close() }
            }
        }
    }

    companion object {
        const val EXTRA_REQ_ID = "ksu.req_id"
        const val EXTRA_UID = "ksu.uid"
        const val EXTRA_COMM = "ksu.comm"
        const val EXTRA_SOCKET = "ksu.socket"
        const val EXTRA_NONCE = "ksu.nonce"

        // Must match MsudReply in msud.cpp.
        private const val WIRE_MAGIC = 0x4D535544 // "MSUD"
        private const val WIRE_SIZE = 20
    }
}

private const val COUNTDOWN_SECONDS = 10

@Composable
private fun SuRequestCard(
    appLabel: String,
    packageName: String,
    uid: Int,
    icon: ImageBitmap?,
    onChoice: (SuRequestActivity.Choice) -> Unit,
) {
    var remaining by remember { mutableIntStateOf(COUNTDOWN_SECONDS) }
    LaunchedEffect(Unit) {
        while (remaining > 0) {
            delay(1000)
            remaining--
        }
        onChoice(SuRequestActivity.Choice.DENY)
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .widthIn(max = 420.dp),
        shape = MaterialTheme.shapes.large,
        tonalElevation = 6.dp,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (icon != null) {
                    Image(
                        bitmap = icon,
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                    )
                }
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = appLabel,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    if (packageName.isNotEmpty() && packageName != appLabel) {
                        Text(
                            text = packageName,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        text = "UID $uid",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Text(
                text = stringResource(R.string.su_request_desc),
                style = MaterialTheme.typography.bodyMedium,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { onChoice(SuRequestActivity.Choice.ALLOW_FOREVER) },
                    modifier = Modifier.weight(1f),
                ) { Text(stringResource(R.string.su_request_allow_forever)) }
                FilledTonalButton(
                    onClick = { onChoice(SuRequestActivity.Choice.ALLOW_ONCE) },
                    modifier = Modifier.weight(1f),
                ) { Text(stringResource(R.string.su_request_allow_once)) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { onChoice(SuRequestActivity.Choice.DENY) },
                    modifier = Modifier.weight(1f),
                ) { Text("${stringResource(R.string.su_request_deny)}（${remaining}s）") }
                OutlinedButton(
                    onClick = { onChoice(SuRequestActivity.Choice.DENY_HIDE) },
                    modifier = Modifier.weight(1f),
                ) { Text(stringResource(R.string.su_request_deny_hide)) }
            }
        }
    }
}
