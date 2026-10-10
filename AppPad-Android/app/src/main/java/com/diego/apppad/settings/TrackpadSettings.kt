package com.diego.apppad.settings

import android.content.Context
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf

/**
 * Trackpad user settings with Compose-observable state, persisted to
 * SharedPreferences. The full settings/remap screen arrives in Step 4; the
 * trackpad surface exposes these inline for now.
 */
class TrackpadSettings(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val naturalScrollState = mutableStateOf(prefs.getBoolean(KEY_NATURAL_SCROLL, DEFAULT_NATURAL_SCROLL))
    private val hapticsEnabledState = mutableStateOf(prefs.getBoolean(KEY_HAPTICS_ENABLED, DEFAULT_HAPTICS_ENABLED))
    private val hapticIntensityState = mutableFloatStateOf(prefs.getFloat(KEY_HAPTIC_INTENSITY, DEFAULT_HAPTIC_INTENSITY))

    /** Natural scrolling: invert scroll axes to match macOS defaults. */
    var naturalScroll: Boolean
        get() = naturalScrollState.value
        set(value) {
            naturalScrollState.value = value
            prefs.edit().putBoolean(KEY_NATURAL_SCROLL, value).apply()
        }

    var hapticsEnabled: Boolean
        get() = hapticsEnabledState.value
        set(value) {
            hapticsEnabledState.value = value
            prefs.edit().putBoolean(KEY_HAPTICS_ENABLED, value).apply()
        }

    /** Haptic intensity, 0..1. */
    var hapticIntensity: Float
        get() = hapticIntensityState.value
        set(value) {
            hapticIntensityState.value = value.coerceIn(0f, 1f)
            prefs.edit().putFloat(KEY_HAPTIC_INTENSITY, hapticIntensityState.value).apply()
        }

    private companion object {
        const val PREFS_NAME = "airpad_settings"
        const val KEY_NATURAL_SCROLL = "natural_scroll"
        const val KEY_HAPTICS_ENABLED = "haptics_enabled"
        const val KEY_HAPTIC_INTENSITY = "haptic_intensity"
        const val DEFAULT_NATURAL_SCROLL = true
        const val DEFAULT_HAPTICS_ENABLED = true
        const val DEFAULT_HAPTIC_INTENSITY = 0.8f
    }
}
