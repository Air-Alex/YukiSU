package com.anatdx.yukisu.ui.util

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FeatureValueParserTest {
    @Test
    fun parsesEnabledStatus() {
        assertTrue(parseFeatureValue(listOf("Feature: yukizygisk", " Status: ENABLED "))!!)
    }

    @Test
    fun parsesDisabledStatus() {
        assertFalse(parseFeatureValue(listOf("Status: disabled"))!!)
    }

    @Test
    fun rejectsMissingOrAmbiguousStatus() {
        assertNull(parseFeatureValue(emptyList()))
        assertNull(parseFeatureValue(listOf("Status: unsupported")))
        assertNull(parseFeatureValue(listOf("Status: enabled", "Status: disabled")))
    }
}
