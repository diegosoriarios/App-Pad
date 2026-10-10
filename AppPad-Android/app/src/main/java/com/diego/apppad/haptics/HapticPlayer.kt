package com.diego.apppad.haptics

import android.content.Context
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.view.HapticFeedbackConstants
import android.view.View
import com.diego.apppad.settings.TrackpadSettings
import java.lang.ref.WeakReference

/**
 * Fake "click" haptics.
 *
 * Intensity is applied on API 30+ via primitive composition scale; below that
 * the intensity selects the effect / amplitude. Fallback ladder:
 *  1. Composed primitive with intensity scale (API 30+)
 *  2. Predefined EFFECT_CLICK / EFFECT_TICK (API 29+)
 *  3. One-shot pulse with scaled amplitude (API 26+)
 *  4. View.performHapticFeedback when no vibrator exists
 */
class HapticPlayer(context: Context, private val settings: TrackpadSettings) {

    private val vibrator: Vibrator? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager)?.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
        }

    private var attachedView: WeakReference<View>? = null

    /** Give the player a View so it can fall back to performHapticFeedback. */
    fun attachView(view: View) {
        attachedView = WeakReference(view)
    }

    /** EFFECT_CLICK — click registered (press). */
    fun click() = play(VibrationEffect.EFFECT_CLICK, pressHaptic = true)

    /** EFFECT_TICK — click released. */
    fun tick() = play(VibrationEffect.EFFECT_TICK, pressHaptic = false)

    private fun play(predefinedEffect: Int, pressHaptic: Boolean) {
        if (!settings.hapticsEnabled) return
        val intensity = settings.hapticIntensity.coerceIn(0f, 1f)
        val vib = vibrator
        when {
            vib == null || !vib.hasVibrator() -> fallback(pressHaptic)

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> {
                if (vib.areAllPrimitivesSupported(predefinedEffect)) {
                    vib.vibrate(
                        VibrationEffect.startComposition()
                            .addPrimitive(predefinedEffect, intensity.coerceIn(0.1f, 1f))
                            .compose()
                    )
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    vib.vibrate(VibrationEffect.createPredefined(predefinedEffect))
                } else {
                    fallback(pressHaptic)
                }
            }

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                vib.vibrate(VibrationEffect.createPredefined(predefinedEffect))

            else -> fallback(pressHaptic)
        }
    }

    private fun fallback(pressHaptic: Boolean) {
        val vib = vibrator
        if (vib != null && vib.hasVibrator()) {
            val amplitude = ((0.15f + 0.85f * settings.hapticIntensity.coerceIn(0f, 1f)) * 255f)
                .toInt()
                .coerceIn(1, 255)
            vib.vibrate(
                VibrationEffect.createOneShot(
                    if (pressHaptic) 24L else 12L,
                    amplitude
                )
            )
        } else {
            attachedView?.get()?.performHapticFeedback(
                if (pressHaptic) HapticFeedbackConstants.VIRTUAL_KEY else HapticFeedbackConstants.CLOCK_TICK
            )
        }
    }
}
