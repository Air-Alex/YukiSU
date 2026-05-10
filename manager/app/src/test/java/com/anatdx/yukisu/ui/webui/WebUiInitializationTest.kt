package com.anatdx.yukisu.ui.webui

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebUiInitializationTest {
    @Test
    fun failedConnectionReturnsWithoutPolling() = runBlocking {
        assertFalse(initializeWebUi { false })
    }

    @Test
    fun missingServiceCallbackTimesOutAndCancelsConnection() = runBlocking {
        var cancelled = false
        val result = initializeWebUi(timeoutMillis = 20) {
            try {
                awaitCancellation()
            } finally {
                cancelled = true
            }
        }
        assertFalse(result)
        assertTrue(cancelled)
    }

    @Test
    fun leavingActivityPropagatesCancellation() = runBlocking {
        val started = CompletableDeferred<Unit>()
        var reportedFailure = false
        val job = async {
            initializeWebUi(onFailure = { reportedFailure = true }) {
                started.complete(Unit)
                awaitCancellation()
            }
        }
        started.await()
        job.cancelAndJoin()
        assertTrue(job.isCancelled)
        assertFalse(reportedFailure)
    }

    @Test
    fun connectionExceptionIsReportedAndCanBeRetried() = runBlocking {
        val failure = IllegalStateException("binder disconnected")
        var reported: Exception? = null
        assertFalse(initializeWebUi(onFailure = { reported = it }) { throw failure })
        assertTrue(reported is IllegalStateException)
        assertEquals(failure.message, reported?.message)
        assertTrue(initializeWebUi { true })
    }
}
