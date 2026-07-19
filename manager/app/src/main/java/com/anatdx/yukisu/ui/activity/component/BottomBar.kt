package com.anatdx.yukisu.ui.activity.component

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SettingsSuggest
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavHostController
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.spec.RouteOrDirection
import com.ramcosta.composedestinations.utils.isRouteOnBackStackAsState
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import com.anatdx.yukisu.ui.MainActivity
import com.anatdx.yukisu.ui.component.YukiIcon
import com.anatdx.yukisu.ui.activity.util.*
import com.anatdx.yukisu.ui.screen.BottomBarDestination
import com.anatdx.yukisu.ui.theme.CardConfig.cardElevation
import com.anatdx.yukisu.ui.theme.isExpressiveUi
import com.anatdx.yukisu.ui.util.*

@SuppressLint("ContextCastToActivity")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BottomBar(navController: NavHostController) {
    val navigator = navController.rememberDestinationsNavigator()
    val isFullFeatured by AppData.DataRefreshManager.isFullFeatured.collectAsState()
    val cardColor = MaterialTheme.colorScheme.surfaceContainer
    val activity = LocalContext.current as MainActivity
    val settings by activity.settingsStateFlow.collectAsState()

    val isHideOtherInfo = settings.isHideOtherInfo

    // 收集计数数据
    val superuserCount by AppData.DataRefreshManager.superuserCount.collectAsState()
    val moduleCount by AppData.DataRefreshManager.moduleCount.collectAsState()


    val destinations = BottomBarDestination.entries.filter {
        isFullFeatured || !it.rootRequired
    }
    val containerColor = cardColor

    fun navigate(destination: BottomBarDestination, selected: Boolean) {
        if (selected) navigator.popBackStack(destination.direction, false)
        navigator.navigate(destination.direction) {
            popUpTo(NavGraphs.root) { saveState = true }
            launchSingleTop = true
            restoreState = true
        }
    }

    if (isExpressiveUi) {
        ShortNavigationBar(
            containerColor = containerColor,
            windowInsets = WindowInsets.navigationBars.only(
                WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom
            ),
            arrangement = ShortNavigationBarArrangement.EqualWeight
        ) {
            destinations.forEach { destination ->
                val selected by navController.isRouteOnBackStackAsState(destination.direction)
                val badgeCount = when (destination) {
                    BottomBarDestination.SuperUser -> superuserCount
                    BottomBarDestination.Module -> moduleCount
                    else -> 0
                }
                ShortNavigationBarItem(
                    selected = selected,
                    onClick = { navigate(destination, selected) },
                    icon = {
                        DestinationIcon(destination, selected, badgeCount, !isHideOtherInfo)
                    },
                    label = {
                        Text(
                            stringResource(destination.label),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                )
            }
        }
    } else {
        NavigationBar(
            modifier = Modifier.windowInsetsPadding(
                WindowInsets.navigationBars.only(WindowInsetsSides.Horizontal)
            ),
            containerColor = containerColor,
            tonalElevation = cardElevation
        ) {
            destinations.forEach { destination ->
                val selected by navController.isRouteOnBackStackAsState(destination.direction)
                val badgeCount = when (destination) {
                    BottomBarDestination.SuperUser -> superuserCount
                    BottomBarDestination.Module -> moduleCount
                    else -> 0
                }
                NavigationBarItem(
                    selected = selected,
                    onClick = { navigate(destination, selected) },
                    icon = {
                        DestinationIcon(destination, selected, badgeCount, !isHideOtherInfo)
                    },
                    label = {
                        Text(
                            stringResource(destination.label),
                            style = MaterialTheme.typography.labelMedium
                        )
                    },
                    alwaysShowLabel = false
                )
            }
        }
    }
}

@Composable
private fun DestinationIcon(
    destination: BottomBarDestination,
    selected: Boolean,
    badgeCount: Int,
    showBadge: Boolean
) {
    val icon: @Composable () -> Unit = {
        val imageVector = if (isExpressiveUi && destination == BottomBarDestination.Settings) {
            Icons.Filled.SettingsSuggest
        } else if (selected) {
            destination.iconSelected
        } else {
            destination.iconNotSelected
        }
        YukiIcon(
            imageVector = imageVector,
            contentDescription = stringResource(destination.label)
        )
    }

    if (destination != BottomBarDestination.SuperUser &&
        destination != BottomBarDestination.Module
    ) {
        icon()
        return
    }

    BadgedBox(
        badge = {
            if (badgeCount > 0 && showBadge) {
                Badge(containerColor = MaterialTheme.colorScheme.secondary) {
                    Text(badgeCount.toString(), style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    ) {
        icon()
    }
}
