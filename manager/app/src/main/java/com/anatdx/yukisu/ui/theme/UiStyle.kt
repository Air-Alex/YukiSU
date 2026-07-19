package com.anatdx.yukisu.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.unit.dp

enum class UiStyle(val persistedValue: String) {
    Classic("classic"),
    Expressive("expressive");

    companion object {
        fun fromPersistedValue(value: String?): UiStyle =
            entries.firstOrNull { it.persistedValue == value } ?: Classic
    }
}

val LocalUiStyle = staticCompositionLocalOf { UiStyle.Classic }

val isExpressiveUi: Boolean
    @Composable
    @ReadOnlyComposable
    get() = LocalUiStyle.current == UiStyle.Expressive

val ExpressiveListGroupMinHeight = 64.dp

val ExpressiveShapes = Shapes(
    extraSmall = RoundedCornerShape(10.dp),
    small = RoundedCornerShape(14.dp),
    medium = RoundedCornerShape(20.dp),
    large = RoundedCornerShape(28.dp),
    extraLarge = RoundedCornerShape(36.dp),
    largeIncreased = RoundedCornerShape(32.dp),
    extraLargeIncreased = RoundedCornerShape(44.dp),
    extraExtraLarge = RoundedCornerShape(56.dp)
)
