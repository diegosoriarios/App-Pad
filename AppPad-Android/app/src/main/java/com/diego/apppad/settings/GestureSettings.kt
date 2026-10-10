package com.diego.apppad.settings

import android.content.Context
import androidx.compose.runtime.mutableStateOf
import com.diego.apppad.gesture.GestureAction
import com.diego.apppad.gesture.GestureDirection
import com.diego.apppad.gesture.GestureOrigin

/**
 * Pure gesture-slot mapping (origin + direction -> action). No Android
 * dependencies so it is fully unit-testable; [GestureSettings] persists it.
 */
class GestureSlots(initial: Map<Slot, GestureAction> = defaultSlots()) {

    data class Slot(val origin: Int, val direction: Int)

    private val slots = HashMap(initial)

    fun action(origin: Int, direction: Int): GestureAction =
        slots[Slot(origin, direction)] ?: GestureAction.DISABLED

    fun set(origin: Int, direction: Int, action: GestureAction) {
        slots[Slot(origin, direction)] = action
    }

    fun snapshot(): Map<Slot, GestureAction> = slots.toMap()

    companion object {
        /** macOS defaults: three- and four-finger swipes mirror System Settings' "3 or 4 fingers". */
        fun defaultSlots(): Map<Slot, GestureAction> = buildMap {
            for (origin in intArrayOf(GestureOrigin.THREE_FINGER_SWIPE, GestureOrigin.FOUR_FINGER_SWIPE)) {
                put(Slot(origin, GestureDirection.UP), GestureAction.MISSION_CONTROL)
                put(Slot(origin, GestureDirection.DOWN), GestureAction.APP_EXPOSE)
                put(Slot(origin, GestureDirection.LEFT), GestureAction.SPACE_NEXT)
                put(Slot(origin, GestureDirection.RIGHT), GestureAction.SPACE_PREV)
            }
        }
    }
}

/**
 * Gesture enable/disable/remap settings, persisted to SharedPreferences and
 * observable from Compose (reads of [threeFingerDrag], [revision] and calls
 * to [action] track the current values).
 */
class GestureSettings(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val slotsState = mutableStateOf(loadSlots())
    private val dragState = mutableStateOf(prefs.getBoolean(KEY_THREE_FINGER_DRAG, DEFAULT_THREE_FINGER_DRAG))

    /** Bumped on every change so Compose readers can observe slot updates. */
    val revision: Int get() = slotsState.value.hashCode() + dragState.value.hashCode()

    var threeFingerDrag: Boolean
        get() = dragState.value
        set(value) {
            dragState.value = value
            prefs.edit().putBoolean(KEY_THREE_FINGER_DRAG, value).apply()
        }

    fun action(origin: Int, direction: Int): GestureAction = slotsState.value.action(origin, direction)

    fun setAction(origin: Int, direction: Int, action: GestureAction) {
        val updated = GestureSlots(slotsState.value.snapshot())
        updated.set(origin, direction, action)
        slotsState.value = updated
        prefs.edit().putString(slotKey(origin, direction), action.name).apply()
    }

    private fun loadSlots(): GestureSlots {
        val slots = GestureSlots()
        for ((slot, _) in GestureSlots.defaultSlots()) {
            val stored = prefs.getString(slotKey(slot.origin, slot.direction), null)
            val parsed = stored?.let { runCatching { GestureAction.valueOf(it) }.getOrNull() }
            if (parsed != null) slots.set(slot.origin, slot.direction, parsed)
        }
        return slots
    }

    private fun slotKey(origin: Int, direction: Int) = "slot_${origin}_$direction"

    private companion object {
        const val PREFS_NAME = "airpad_gesture_settings"
        const val KEY_THREE_FINGER_DRAG = "three_finger_drag"
        const val DEFAULT_THREE_FINGER_DRAG = false
    }
}
