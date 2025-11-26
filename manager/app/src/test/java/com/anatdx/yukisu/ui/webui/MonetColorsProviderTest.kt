package com.anatdx.yukisu.ui.webui

import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class MonetColorsProviderTest {
    @Test
    fun writesCssRgbaRatherThanAndroidArgb() {
        val css = MonetColorsProvider.getColorsCss(
            lightColorScheme(primary = Color(0x80123456), secondary = Color(0xFFABCDEF))
        )
        val properties = parseCss(css)

        assertEquals("#12345680", properties["primary"])
        assertEquals("#abcdef", properties["secondary"])
    }

    @Test
    fun exposesTheUpstreamMaterialPaletteAndComponentAliases() {
        val properties = parseCss(MonetColorsProvider.getColorsCss(lightColorScheme()))

        assertEquals(45, properties.size)
        assertEquals(properties["onPrimaryContainer"], properties["filledCardContentColor"])
        assertEquals(properties["primaryContainer"], properties["filledCardContainerColor"])
        assertEquals(properties["secondaryContainer"], properties["filledTonalButtonContainerColor"])
        assertFalse(properties.getValue("tonalSurface").isEmpty())
        assertFalse(properties.getValue("surfaceContainerLowest").isEmpty())
    }

    private fun parseCss(css: String): Map<String, String> =
        Regex("--([A-Za-z]+): (#[a-f0-9]+);").findAll(css)
            .associate { it.groupValues[1] to it.groupValues[2] }
}
