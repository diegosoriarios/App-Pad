package com.diego.apppad.gesture

/**
 * Semantic actions a recognized gesture can trigger on the Mac.
 * Wire codes are stable and must match the Mac's `GestureAction` catalog
 * (PROTOCOL.md §8 action catalog).
 */
enum class GestureAction(val code: Int) {
    DISABLED(0),
    MISSION_CONTROL(1),
    APP_EXPOSE(2),
    SPACE_NEXT(3),
    SPACE_PREV(4),
    SHOW_DESKTOP(5),
    LAUNCHPAD(6),
    NOTIFICATION_CENTER(7);

    companion object {
        fun fromCode(code: Int): GestureAction? = entries.firstOrNull { it.code == code }
    }
}

/** Raw gestures that can be mapped to actions (PROTOCOL.md §8). */
object GestureOrigin {
    const val THREE_FINGER_SWIPE = 0x01
    const val FOUR_FINGER_SWIPE = 0x02
}

/** Physical finger-travel directions carried in gesture packets. */
object GestureDirection {
    const val UP = 0
    const val DOWN = 1
    const val LEFT = 2
    const val RIGHT = 3
}
