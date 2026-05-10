package com.anatdx.yukisu.ui.webui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ModuleConfigTest {
    @Test
    fun automaticEngineRequiresAnExplicitModulePreference() {
        assertNull(ModuleConfig().resolveEngine("com.anatdx.yukisu"))
        assertNull(ModuleConfig.parse("{}").resolveEngine("com.anatdx.yukisu"))
        assertNull(ModuleConfig.parse("""{"name":"Example"}""").resolveEngine("com.anatdx.yukisu"))
        assertEquals("wx", ModuleConfig.parse("""{"webui-engine":"wx"}""").resolveEngine("com.anatdx.yukisu"))
    }

    @Test
    fun managerPreferenceTakesPriorityOverLegacyFallback() {
        val config = ModuleConfig.parse("""{"webui-engine":{"com.anatdx.yukisu":"ksu","en":"wx"}}""")
        assertEquals("ksu", config.resolveEngine("com.anatdx.yukisu"))
        assertEquals("wx", config.resolveEngine("another.manager"))
    }

    @Test
    fun invalidEngineTypesDoNotOptIntoWebUiX() {
        for (value in listOf("null", "true", "42", "[]", "{}")) {
            assertNull(ModuleConfig.parse("""{"webui-engine":$value}""").resolveEngine("com.anatdx.yukisu"))
        }
    }
}
