package ui.screen.feature

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class SuCompactMode { OFF, TRADITIONAL, KSM }

internal data class SuCompactSnapshot(
    val traditional: Boolean = true,
    val ksm: Boolean = false,
    val magisk: Boolean = false,
) {
    val mode: SuCompactMode
        get() = when {
            ksm -> SuCompactMode.KSM
            traditional -> SuCompactMode.TRADITIONAL
            else -> SuCompactMode.OFF
        }

    fun matches(mode: SuCompactMode): Boolean =
        traditional == (mode == SuCompactMode.TRADITIONAL) &&
            ksm == (mode == SuCompactMode.KSM) &&
            (mode == SuCompactMode.KSM || !magisk)
}

internal class SuCompactController(
    val read: () -> SuCompactSnapshot,
    private val write: suspend (String, Boolean) -> Boolean,
) {
    private val mutex = Mutex()

    suspend fun select(mode: SuCompactMode): Boolean = mutex.withLock {
        transaction { applyMode(mode) && read().matches(mode) }
    }

    suspend fun setMagisk(enabled: Boolean): Boolean = mutex.withLock {
        if (!read().matches(SuCompactMode.KSM)) return@withLock false
        transaction {
            write("magisk_compat", enabled) &&
                read().let { it.matches(SuCompactMode.KSM) && it.magisk == enabled }
        }
    }

    private suspend fun applyMode(mode: SuCompactMode): Boolean {
        if (mode != SuCompactMode.KSM && read().magisk && !write("magisk_compat", false)) {
            return false
        }
        if (read().matches(mode)) return true
        return when (mode) {
            SuCompactMode.TRADITIONAL -> write("su_compat", true)
            SuCompactMode.KSM -> write("kasumi_sucompat", true)
            SuCompactMode.OFF -> {
                if (read().ksm && !write("kasumi_sucompat", false)) return false
                !read().traditional || write("su_compat", false)
            }
        }
    }

    private suspend fun transaction(update: suspend () -> Boolean): Boolean {
        val previous = read()
        if (runCatching { update() }.getOrDefault(false)) return true
        // set-save persists both mutually exclusive features, including rollback.
        runCatching {
            if (read().magisk && !previous.magisk) write("magisk_compat", false)
            if (applyMode(previous.mode) && read().magisk != previous.magisk) {
                write("magisk_compat", previous.magisk)
            }
        }
        return false
    }
}
