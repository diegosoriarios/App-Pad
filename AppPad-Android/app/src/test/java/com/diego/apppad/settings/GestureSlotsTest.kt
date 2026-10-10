package com.diego.apppad.settings

import com.diego.apppad.gesture.GestureAction
import com.diego.apppad.gesture.GestureDirection
import com.diego.apppad.gesture.GestureOrigin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GestureSlotsTest {

    @Test
    fun `defaults mirror macOS three and four finger swipes`() {
        val slots = GestureSlots()
        for (origin in intArrayOf(GestureOrigin.THREE_FINGER_SWIPE, GestureOrigin.FOUR_FINGER_SWIPE)) {
            assertEquals(GestureAction.MISSION_CONTROL, slots.action(origin, GestureDirection.UP))
            assertEquals(GestureAction.APP_EXPOSE, slots.action(origin, GestureDirection.DOWN))
            assertEquals(GestureAction.SPACE_NEXT, slots.action(origin, GestureDirection.LEFT))
            assertEquals(GestureAction.SPACE_PREV, slots.action(origin, GestureDirection.RIGHT))
        }
    }

    @Test
    fun `remap changes only the targeted slot`() {
        val slots = GestureSlots()
        slots.set(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.UP, GestureAction.LAUNCHPAD)
        assertEquals(GestureAction.LAUNCHPAD, slots.action(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.UP))
        assertEquals(GestureAction.MISSION_CONTROL, slots.action(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.UP))
        assertEquals(GestureAction.APP_EXPOSE, slots.action(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.DOWN))
    }

    @Test
    fun `snapshot round trip preserves the mapping`() {
        val slots = GestureSlots()
        slots.set(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.LEFT, GestureAction.DISABLED)
        val copy = GestureSlots(slots.snapshot())
        assertEquals(GestureAction.DISABLED, copy.action(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.LEFT))
        assertEquals(slots.action(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.UP),
            copy.action(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.UP))
    }

    @Test
    fun `action codes are stable for the wire format`() {
        assertEquals(0, GestureAction.DISABLED.code)
        assertEquals(1, GestureAction.MISSION_CONTROL.code)
        assertEquals(2, GestureAction.APP_EXPOSE.code)
        assertEquals(3, GestureAction.SPACE_NEXT.code)
        assertEquals(4, GestureAction.SPACE_PREV.code)
        assertEquals(5, GestureAction.SHOW_DESKTOP.code)
        assertEquals(6, GestureAction.LAUNCHPAD.code)
        assertEquals(7, GestureAction.NOTIFICATION_CENTER.code)
        for (action in GestureAction.entries) {
            assertEquals(action, GestureAction.fromCode(action.code))
        }
        assertNull(GestureAction.fromCode(200))
    }
}
