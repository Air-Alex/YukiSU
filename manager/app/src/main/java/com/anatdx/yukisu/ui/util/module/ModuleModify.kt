package com.anatdx.yukisu.ui.util.module

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import com.anatdx.yukisu.R
import com.anatdx.yukisu.ui.component.YukiAlertDialog
import com.anatdx.yukisu.ksu.KsuPaths
import com.topjohnwu.superuser.io.SuFileInputStream
import com.topjohnwu.superuser.io.SuFileOutputStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

object ModuleModify {
    @Composable
    fun AllowlistRestoreConfirmationDialog(
        showDialog: Boolean,
        onConfirm: () -> Unit,
        onDismiss: () -> Unit
    ) {
        if (showDialog) {
            YukiAlertDialog(
                onDismissRequest = onDismiss,
                title = {
                    Text(
                        text = stringResource(R.string.allowlist_restore_confirm_title)
                    )
                },
                text = {
                    Text(
                        text = stringResource(R.string.allowlist_restore_confirm_message),
                        style = MaterialTheme.typography.bodyMedium
                    )
                },
                confirmButton = {
                    TextButton(onClick = onConfirm) {
                        Text(stringResource(R.string.confirm))
                    }
                },
                dismissButton = {
                    TextButton(onClick = onDismiss) {
                        Text(stringResource(R.string.cancel))
                    }
                }
            )
        }
    }

    suspend fun backupAllowlist(context: Context, snackBarHost: SnackbarHostState, uri: Uri) {
        withContext(Dispatchers.IO) {
            try {
                SuFileInputStream.open(KsuPaths.ALLOWLIST).use { input ->
                    context.contentResolver.openOutputStream(uri)?.use { output ->
                        input.copyTo(output)
                    } ?: throw IOException("Failed to open output uri")
                }

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_backup_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e("AllowlistBackup", context.getString(R.string.allowlist_backup_failed, ""), e)
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_backup_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    suspend fun restoreAllowlist(
        context: Context,
        snackBarHost: SnackbarHostState,
        uri: Uri,
        showConfirmDialog: (Boolean) -> Unit,
        confirmResult: CompletableDeferred<Boolean>
    ) {
        withContext(Dispatchers.Main) {
            showConfirmDialog(true)
        }

        val userConfirmed = confirmResult.await()
        if (!userConfirmed) return

        withContext(Dispatchers.IO) {
            try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    SuFileOutputStream.open(KsuPaths.ALLOWLIST).use { output ->
                        input.copyTo(output)
                    }
                } ?: throw IOException("Failed to open input uri")

                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_restore_success),
                        duration = SnackbarDuration.Long
                    )
                }

            } catch (e: Exception) {
                Log.e(
                    "AllowlistRestore",
                    context.getString(R.string.allowlist_restore_failed, ""),
                    e
                )
                withContext(Dispatchers.Main) {
                    snackBarHost.showSnackbar(
                        context.getString(R.string.allowlist_restore_failed, e.message),
                        duration = SnackbarDuration.Long
                    )
                }
            }
        }
    }

    @Composable
    fun rememberAllowlistBackupLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: CoroutineScope = rememberCoroutineScope()
    ) = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                scope.launch {
                    backupAllowlist(context, snackBarHost, uri)
                }
            }
        }
    }

    @Composable
    fun rememberAllowlistRestoreLauncher(
        context: Context,
        snackBarHost: SnackbarHostState,
        scope: CoroutineScope = rememberCoroutineScope()
    ): ActivityResultLauncher<Intent> {
        var showAllowlistRestoreDialog by remember { mutableStateOf(false) }
        var allowlistRestoreConfirmResult by remember {
            mutableStateOf<CompletableDeferred<Boolean>?>(
                null
            )
        }

        AllowlistRestoreConfirmationDialog(
            showDialog = showAllowlistRestoreDialog,
            onConfirm = {
                showAllowlistRestoreDialog = false
                allowlistRestoreConfirmResult?.complete(true)
            },
            onDismiss = {
                showAllowlistRestoreDialog = false
                allowlistRestoreConfirmResult?.complete(false)
            }
        )

        return rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                result.data?.data?.let { uri ->
                    scope.launch {
                        val confirmResult = CompletableDeferred<Boolean>()
                        allowlistRestoreConfirmResult = confirmResult

                        restoreAllowlist(
                            context = context,
                            snackBarHost = snackBarHost,
                            uri = uri,
                            showConfirmDialog = { show -> showAllowlistRestoreDialog = show },
                            confirmResult = confirmResult
                        )
                    }
                }
            }
        }
    }

    fun createAllowlistBackupIntent(): Intent {
        return Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            putExtra(Intent.EXTRA_TITLE, "ksu_allowlist_backup_$timestamp.dat")
        }
    }

    fun createAllowlistRestoreIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
        }
    }
}
