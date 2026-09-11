package com.anatdx.yukisu.ui.kasumi

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.anatdx.yukisu.R
import com.anatdx.yukisu.ui.component.YukiIcon
import com.anatdx.yukisu.ui.component.YukiAlertDialog
import com.anatdx.yukisu.ui.theme.isExpressiveUi
import com.anatdx.yukisu.ui.kasumi.util.KasumiManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

private val KASUMI_MOUNT_MODES = listOf("auto", "kasumi", "overlay", "magic", "none")

internal val KASUMI_MODE_COLORS = mapOf(
    "auto" to Color(0xFF1976D2),
    "kasumi" to Color(0xFF388E3C),
    "overlay" to Color(0xFFF57C00),
    "magic" to Color(0xFF7B1FA2),
    "none" to Color(0xFF616161)
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun KasumiMountConfigDialog(
    moduleId: String,
    moduleName: String,
    initialInfo: KasumiManager.ModuleInfo?,
    kasumiAvailable: Boolean,
    globalMode: String,
    onDismiss: () -> Unit,
    onSaved: () -> Unit
) {
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    val selectableModes = KASUMI_MOUNT_MODES.filter { it != "kasumi" || kasumiAvailable }

    var selectedMode by remember(moduleId) {
        mutableStateOf(initialInfo?.mode ?: "auto")
    }
    var rules by remember(moduleId) {
        mutableStateOf(initialInfo?.rules ?: emptyList<KasumiManager.ModuleRule>())
    }
    var newPath by remember { mutableStateOf("") }
    var newMode by remember { mutableStateOf(if (kasumiAvailable) "kasumi" else "overlay") }
    var editingPath by remember { mutableStateOf<String?>(null) }
    var modeExpanded by remember { mutableStateOf(false) }
    var isSaving by remember { mutableStateOf(false) }
    var rulesExpanded by remember { mutableStateOf(false) }

    val modeLabels = mapOf(
        "auto" to stringResource(R.string.kasumi_mount_mode_auto),
        "kasumi" to stringResource(R.string.kasumi_mount_mode_kasumi),
        "overlay" to stringResource(R.string.kasumi_mount_mode_overlay),
        "magic" to stringResource(R.string.kasumi_mount_mode_magic),
        "none" to stringResource(R.string.kasumi_mount_mode_none),
        "hide" to stringResource(R.string.kasumi_mount_mode_hide),
    )

    YukiAlertDialog(
        onDismissRequest = { if (!isSaving) onDismiss() },
        title = {
            Column {
                Text(stringResource(R.string.kasumi_mount_config))
                Text(
                    text = moduleName,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (globalMode != "auto") Text(stringResource(R.string.kasumi_global_override, globalMode))
                Text(
                    text = stringResource(R.string.kasumi_mount_mode),
                    style = MaterialTheme.typography.titleSmall
                )
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    selectableModes.forEach { mode ->
                        FilterChip(
                            selected = selectedMode == mode,
                            onClick = { selectedMode = mode },
                            enabled = !isSaving,
                            label = { Text(modeLabels[mode] ?: mode) },
                            leadingIcon = {
                                if (isExpressiveUi) {
                                    YukiIcon(
                                        if (selectedMode == mode) Icons.Outlined.Check else when (mode) {
                                            "kasumi" -> Icons.Outlined.Memory
                                            "overlay" -> Icons.Outlined.Layers
                                            "magic" -> Icons.Outlined.AutoFixHigh
                                            "none" -> Icons.Outlined.Block
                                            else -> Icons.Outlined.Settings
                                        },
                                        null, Modifier.size(FilterChipDefaults.IconSize),
                                    )
                                } else {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .background(
                                                KASUMI_MODE_COLORS[mode] ?: MaterialTheme.colorScheme.primary,
                                                RoundedCornerShape(4.dp)
                                            )
                                    )
                                }
                            }
                        )
                    }
                }

                if (!isExpressiveUi) HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .then(if (isExpressiveUi) Modifier.clip(MaterialTheme.shapes.large)
                            .background(MaterialTheme.colorScheme.surfaceContainerHigh) else Modifier)
                        .clickable { rulesExpanded = !rulesExpanded }
                        .padding(horizontal = if (isExpressiveUi) 16.dp else 0.dp, vertical = if (isExpressiveUi) 16.dp else 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.kasumi_module_rules_title),
                        style = if (isExpressiveUi) MaterialTheme.typography.titleMedium else MaterialTheme.typography.titleSmall
                    )
                    YukiIcon(
                        imageVector = if (rulesExpanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                        contentDescription = null
                    )
                }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .animateContentSize(
                            animationSpec = tween(280, easing = FastOutSlowInEasing)
                        )
                ) {
                    if (rulesExpanded) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                        rules.forEach { rule: KasumiManager.ModuleRule ->
                            Row(
                                modifier = Modifier.fillMaxWidth().then(
                                    if (isExpressiveUi) Modifier.clip(MaterialTheme.shapes.medium)
                                        .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                                        .padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp)
                                    else Modifier),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "${rule.path} → ${rule.mode}",
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.weight(1f),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                IconButton(
                                    enabled = !isSaving,
                                    onClick = { editingPath = rule.path; newPath = rule.path; newMode = rule.mode }
                                ) { YukiIcon(Icons.Outlined.Edit, stringResource(R.string.kasumi_edit_rule)) }
                                IconButton(
                                    enabled = !isSaving,
                                    onClick = {
                                        rules = rules.filter { r -> r != rule }
                                        if (editingPath == rule.path) { editingPath = null; newPath = "" }
                                    }
                                ) {
                                    YukiIcon(Icons.Outlined.Delete, contentDescription = null)
                                }
                            }
                        }
                        OutlinedTextField(
                            value = newPath,
                            onValueChange = { newPath = it },
                            enabled = !isSaving,
                            isError = newPath.isNotEmpty() && (!newPath.startsWith("/") || rules.any { it.path == newPath.trim() && it.path != editingPath }),
                            placeholder = { Text(stringResource(R.string.kasumi_module_rules_placeholder)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box {
                                FilledTonalButton(
                                    enabled = !isSaving,
                                    onClick = { modeExpanded = true },
                                    shape = if (isExpressiveUi) ButtonDefaults.shape else RoundedCornerShape(20.dp)
                                ) {
                                    Text(modeLabels[newMode] ?: newMode)
                                    YukiIcon(Icons.Outlined.ArrowDropDown, contentDescription = null)
                                }
                                DropdownMenu(
                                    expanded = modeExpanded,
                                    onDismissRequest = { modeExpanded = false }
                                ) {
                                    selectableModes.filter { it != "auto" || newMode == "auto" }.forEach { mode ->
                                        DropdownMenuItem(
                                            text = { Text(modeLabels[mode] ?: mode) },
                                            onClick = {
                                                newMode = mode
                                                modeExpanded = false
                                            }
                                        )
                                    }
                                }
                            }
                            FilledTonalButton(
                                enabled = !isSaving && newPath.startsWith('/') && rules.none { it.path == newPath.trim() && it.path != editingPath },
                                onClick = {
                                    if (newPath.startsWith("/")) {
                                        rules = rules.filterNot { it.path == editingPath } + KasumiManager.ModuleRule(newPath.trim(), newMode)
                                        newPath = ""
                                        editingPath = null
                                    }
                                },
                                shape = if (isExpressiveUi) ButtonDefaults.shape else RoundedCornerShape(20.dp)
                            ) {
                                Text(stringResource(if (editingPath == null) R.string.kasumi_module_rules_add else R.string.kasumi_rule_save))
                            }
                        }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (isSaving) return@Button
                    isSaving = true
                    scope.launch {
                        val rulesToSave = if (newPath.isNotEmpty()) rules.filterNot { it.path == editingPath } +
                            KasumiManager.ModuleRule(newPath.trim(), newMode) else rules
                        try {
                            KasumiManager.saveModule(moduleId, selectedMode, rulesToSave)
                            onSaved()
                        } catch (e: Exception) {
                            if (e is CancellationException) throw e
                            error = e.message ?: resources.getString(R.string.operation_failed)
                        } finally {
                            isSaving = false
                        }
                    }
                },
                enabled = !isSaving && (newPath.isEmpty() || (newPath.startsWith('/') && rules.none { it.path == newPath.trim() && it.path != editingPath }))
            ) {
                Text(stringResource(android.R.string.ok))
            }
        },
        dismissButton = {
            TextButton(enabled = !isSaving, onClick = onDismiss) {
                Text(stringResource(android.R.string.cancel))
            }
        }
    )
}
