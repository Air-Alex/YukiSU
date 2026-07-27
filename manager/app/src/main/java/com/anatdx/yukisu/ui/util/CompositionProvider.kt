package com.anatdx.yukisu.ui.util

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.compositionLocalOf

val LocalSnackbarHost = compositionLocalOf<SnackbarHostState> {
    error("CompositionLocal LocalSnackbarController not present")
}

class NavigationLeaveGuard {
    private data class Registration(
        val owner: Any,
        val route: String,
        val interceptor: ((() -> Unit) -> Unit),
    )

    private var registration: Registration? = null

    fun register(
        owner: Any,
        route: String,
        interceptor: ((() -> Unit) -> Unit),
    ) {
        registration = Registration(owner, route, interceptor)
    }

    fun unregister(owner: Any) {
        if (registration?.owner === owner) {
            registration = null
        }
    }

    fun navigateOrIntercept(route: String?, navigate: () -> Unit) {
        val current = registration
        if (current != null && current.route == route) {
            current.interceptor(navigate)
        } else {
            navigate()
        }
    }
}

val LocalNavigationLeaveGuard = compositionLocalOf<NavigationLeaveGuard> {
    error("CompositionLocal LocalNavigationLeaveGuard not present")
}
