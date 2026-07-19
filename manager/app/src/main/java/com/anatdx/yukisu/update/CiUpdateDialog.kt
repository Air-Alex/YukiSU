package com.anatdx.yukisu.update

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.anatdx.yukisu.BuildConfig
import com.anatdx.yukisu.R
import com.anatdx.yukisu.ui.component.YukiAlertDialog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class CiUpdateStage {
    READY,
    DOWNLOADING,
    VERIFYING,
    INSTALLING,
    FAILED,
}

@Composable
fun CiUpdateDialog() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var run by remember { mutableStateOf<CiRun?>(null) }
    var stage by remember { mutableStateOf(CiUpdateStage.READY) }
    var progress by remember { mutableIntStateOf(0) }
    var error by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        val settings = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val updateChecksEnabled = settings.getBoolean("check_update", true)
        val ciUpdateChecksEnabled = settings.getBoolean("check_ci_update", false)
        if (!updateChecksEnabled || !ciUpdateChecksEnabled) return@LaunchedEffect

        runCatching { CiUpdateManager.latestSuccessfulMainRun() }
            .getOrNull()
            ?.takeIf { it.runId > BuildConfig.CI_RUN_ID }
            ?.let { run = it }
    }

    val availableRun = run ?: return
    val busy = stage == CiUpdateStage.DOWNLOADING ||
        stage == CiUpdateStage.VERIFYING ||
        stage == CiUpdateStage.INSTALLING

    fun beginUpdate() {
        scope.launch {
            try {
                error = ""
                progress = 0
                stage = CiUpdateStage.DOWNLOADING
                val prepared = CiUpdateManager.downloadAndExtract(context) { downloaded ->
                    progress = downloaded
                }
                stage = CiUpdateStage.VERIFYING
                withContext(Dispatchers.IO) {
                    CiUpdateManager.verify(context, availableRun, prepared)
                }
                stage = CiUpdateStage.INSTALLING
                when (CiUpdateManager.install(context, prepared.apk)) {
                    CiInstallResult.RootInstalled -> Toast.makeText(
                        context,
                        R.string.ci_update_root_installed,
                        Toast.LENGTH_LONG,
                    ).show()
                    CiInstallResult.SystemInstallerStarted -> Unit
                }
                run = null
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (throwable: Exception) {
                error = throwable.message ?: throwable.javaClass.simpleName
                stage = CiUpdateStage.FAILED
            }
        }
    }

    YukiAlertDialog(
        onDismissRequest = { if (!busy) run = null },
        title = { Text(stringResource(R.string.ci_update_title)) },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    stringResource(
                        R.string.ci_update_message,
                        availableRun.runId,
                        BuildConfig.CI_RUN_ID,
                    )
                )
                when (stage) {
                    CiUpdateStage.READY -> Unit
                    CiUpdateStage.DOWNLOADING -> {
                        Spacer(Modifier.height(16.dp))
                        LinearProgressIndicator(
                            progress = { progress / 100f },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.ci_update_downloading, progress))
                    }
                    CiUpdateStage.VERIFYING -> {
                        Spacer(Modifier.height(16.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.ci_update_verifying))
                    }
                    CiUpdateStage.INSTALLING -> {
                        Spacer(Modifier.height(16.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(R.string.ci_update_installing))
                    }
                    CiUpdateStage.FAILED -> {
                        Spacer(Modifier.height(16.dp))
                        Text(stringResource(R.string.ci_update_failed, error))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = ::beginUpdate, enabled = !busy) {
                Text(
                    stringResource(
                        if (stage == CiUpdateStage.FAILED) {
                            R.string.ci_update_retry
                        } else {
                            R.string.ci_update_download
                        }
                    )
                )
            }
        },
        dismissButton = {
            TextButton(onClick = { run = null }, enabled = !busy) {
                Text(stringResource(android.R.string.cancel))
            }
        },
        properties = DialogProperties(
            dismissOnBackPress = !busy,
            dismissOnClickOutside = !busy,
        ),
    )
}
