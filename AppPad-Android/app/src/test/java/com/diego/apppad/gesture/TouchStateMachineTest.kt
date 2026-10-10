package com.diego.apppad.gesture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class TouchStateMachineTest {

    private lateinit var machine: TouchStateMachine

    @Before
    fun setUp() {
        machine = TouchStateMachine()
    }

    private fun p(id: Long, x: Float, y: Float) = TouchPoint(id, x, y)

    @Test
    fun `single finger quick tap emits left click press and release`() {
        val down = machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        assertTrue(down.isEmpty())

        val up = machine.onPointerEvent(100L, emptyList())
        assertEquals(2, up.size)
        assertEquals(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.PRESS), up[0])
        assertEquals(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.RELEASE), up[1])
    }

    @Test
    fun `slow tap is not a click`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        val up = machine.onPointerEvent(400L, emptyList())
        assertTrue(up.none { it is GestureEvent.Click })
    }

    @Test
    fun `single finger move beyond slop emits accelerated move events`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(30L, listOf(p(1L, 110f, 100f))) // 10px, still within slop

        val events = machine.onPointerEvent(60L, listOf(p(1L, 170f, 100f))) // total 70px
        val moves = events.filterIsInstance<GestureEvent.Move>()
        assertTrue(moves.isNotEmpty())
        assertTrue(moves.last().dx > 0f)
        assertEquals(0f, moves.last().dy, 0.001f)
        assertTrue(events.none { it is GestureEvent.Click })
    }

    @Test
    fun `two finger quick tap emits right click press and release`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(20L, listOf(p(1L, 100f, 100f), p(2L, 200f, 100f)))

        val up = machine.onPointerEvent(80L, emptyList())
        assertEquals(2, up.size)
        assertEquals(GestureEvent.Click(GestureEvent.Click.Button.RIGHT, GestureEvent.Click.Phase.PRESS), up[0])
        assertEquals(GestureEvent.Click(GestureEvent.Click.Button.RIGHT, GestureEvent.Click.Phase.RELEASE), up[1])
    }

    @Test
    fun `two finger drag scrolls then momentum decays to stop`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(20L, listOf(p(1L, 100f, 100f), p(2L, 200f, 100f)))

        // Ramp: 10px, below SCROLL_RAMP_PX
        val ramp = machine.onPointerEvent(40L, listOf(p(1L, 100f, 110f), p(2L, 200f, 110f)))
        assertTrue(ramp.none { it is GestureEvent.Scroll })

        // Travel: +20px centroid movement
        val scroll = machine.onPointerEvent(60L, listOf(p(1L, 100f, 130f), p(2L, 200f, 130f)))
        val scrollEvents = scroll.filterIsInstance<GestureEvent.Scroll>()
        assertTrue(scrollEvents.isNotEmpty())
        assertFalse(scrollEvents.first().isMomentum)
        assertTrue(scrollEvents.first().dy > 0f)

        // Lift with velocity -> momentum engaged
        machine.onPointerEvent(80L, emptyList())
        // Session ended inside the two-finger window but with movement > tap slop
        val momentum = machine.onTick(96L)
        val momentumScroll = momentum.filterIsInstance<GestureEvent.Scroll>()
        assertTrue(momentumScroll.isNotEmpty())
        assertTrue(momentumScroll.first().isMomentum)
        assertTrue(momentumScroll.first().dy > 0f)
        assertTrue(machine.isMomentumActive)

        // Momentum decays until it stops
        var now = 96L
        var stopped = false
        repeat(200) {
            now += 16L
            val ticks = machine.onTick(now)
            if (!machine.isMomentumActive) {
                stopped = true
                assertTrue(ticks.isEmpty())
            }
        }
        assertTrue(stopped)
    }

    @Test
    fun `tap followed by move starts click and drag`() {
        // Tap
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        val tap = machine.onPointerEvent(100L, emptyList())
        assertEquals(2, tap.count { it is GestureEvent.Click })

        // New touch shortly after, moving past drag slop
        machine.onPointerEvent(200L, listOf(p(1L, 100f, 100f)))
        val drag = machine.onPointerEvent(230L, listOf(p(1L, 118f, 100f))) // 18px > DRAG_SLOP_PX (12)

        val presses = drag.filterIsInstance<GestureEvent.Click>()
            .filter { it.phase == GestureEvent.Click.Phase.PRESS }
        assertEquals(1, presses.size)
        assertEquals(GestureEvent.Click.Button.LEFT, presses.first().button)
        assertTrue(drag.any { it is GestureEvent.Move })

        // Lift releases the drag
        val release = machine.onPointerEvent(300L, emptyList())
        val releases = release.filterIsInstance<GestureEvent.Click>()
            .filter { it.phase == GestureEvent.Click.Phase.RELEASE }
        assertEquals(1, releases.size)
    }

    @Test
    fun `new contact interrupts momentum`() {
        // Establish momentum via a fast two-finger scroll
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(20L, listOf(p(1L, 100f, 100f), p(2L, 200f, 100f)))
        machine.onPointerEvent(40L, listOf(p(1L, 100f, 130f), p(2L, 200f, 130f)))
        machine.onPointerEvent(60L, emptyList())

        // Drive momentum until active
        var now = 60L
        while (!machine.isMomentumActive && now < 2000L) {
            now += 16L
            machine.onTick(now)
        }
        assertTrue(machine.isMomentumActive)

        // A new touch must stop inertia
        val events = machine.onPointerEvent(now + 16L, listOf(p(3L, 50f, 50f)))
        assertFalse(machine.isMomentumActive)
        assertTrue(events.isEmpty())
    }

    @Test
    fun `cancel resets to idle`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.cancel()
        // Stale up after cancel must not produce a tap
        val up = machine.onPointerEvent(50L, emptyList())
        assertTrue(up.isEmpty())
    }

    // MARK: - Three/four-finger swipes

    private fun threeFingers(y: Float) = listOf(p(1L, 100f, y), p(2L, 200f, y), p(3L, 150f, y + 50f))

    @Test
    fun `three finger swipe up fires swipe event once`() {
        machine.onPointerEvent(0L, threeFingers(200f))

        // 20px centroid travel: below SWIPE_ACTIVATE_PX (30)
        val small = machine.onPointerEvent(30L, threeFingers(180f))
        assertTrue(small.none { it is GestureEvent.Swipe })

        // 80px centroid travel: fires UP exactly once
        val fired = machine.onPointerEvent(60L, threeFingers(120f))
        assertEquals(1, fired.size)
        assertEquals(
            GestureEvent.Swipe(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.UP),
            fired[0]
        )

        // Continuing to move fires nothing more during this contact
        val more = machine.onPointerEvent(90L, threeFingers(60f))
        assertTrue(more.isEmpty())

        // Lift is quiet too (no taps from a multi-finger session)
        val lift = machine.onPointerEvent(120L, emptyList())
        assertTrue(lift.isEmpty())
    }

    @Test
    fun `three finger swipe directions are classified by dominant axis`() {
        machine.onPointerEvent(0L, threeFingers(200f))
        var e = machine.onPointerEvent(50L, threeFingers(260f))
        assertEquals(GestureEvent.Swipe(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.DOWN), e[0])
        machine.onPointerEvent(60L, emptyList())

        machine.onPointerEvent(100L, threeFingers(200f))
        e = machine.onPointerEvent(150L, listOf(p(1L, 60f, 200f), p(2L, 160f, 200f), p(3L, 110f, 250f)))
        assertEquals(GestureEvent.Swipe(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.LEFT), e[0])
        machine.onPointerEvent(160L, emptyList())

        machine.onPointerEvent(200L, threeFingers(200f))
        e = machine.onPointerEvent(250L, listOf(p(1L, 140f, 200f), p(2L, 240f, 200f), p(3L, 190f, 250f)))
        assertEquals(GestureEvent.Swipe(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.RIGHT), e[0])
    }

    @Test
    fun `four finger swipe is reported with four finger origin`() {
        val four = { y: Float ->
            listOf(p(1L, 100f, y), p(2L, 200f, y), p(3L, 150f, y + 50f), p(4L, 150f, y - 50f))
        }
        machine.onPointerEvent(0L, four(200f))
        val e = machine.onPointerEvent(50L, four(160f))
        assertEquals(1, e.size)
        assertEquals(GestureEvent.Swipe(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.UP), e[0])
    }

    @Test
    fun `multi finger contact suppresses move and scroll events`() {
        machine.onPointerEvent(0L, threeFingers(200f))
        val events = machine.onPointerEvent(40L, threeFingers(210f))
        assertTrue(events.none { it is GestureEvent.Move })
        assertTrue(events.none { it is GestureEvent.Scroll })
    }

    @Test
    fun `adding a third finger to a click drag releases the button`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(50L, emptyList()) // tap
        machine.onPointerEvent(100L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(130L, listOf(p(1L, 120f, 100f))) // drag engages (press)
        val between = machine.onPointerEvent(140L, listOf(p(1L, 121f, 100f)))
        assertTrue(between.none { it is GestureEvent.Click })

        // Third finger lands: the held button must be released
        val e = machine.onPointerEvent(150L, listOf(p(1L, 121f, 100f), p(2L, 300f, 100f), p(3L, 400f, 100f)))
        val releases = e.filterIsInstance<GestureEvent.Click>()
            .filter { it.phase == GestureEvent.Click.Phase.RELEASE }
        assertEquals(1, releases.size)

        // Lifting everything stays quiet (no stuck state, no stray click)
        val lift = machine.onPointerEvent(200L, emptyList())
        assertTrue(lift.none { it is GestureEvent.Click })
    }

    // MARK: - Three-finger drag

    @Test
    fun `three finger drag emits press moves and release`() {
        machine.threeFingerDragEnabled = true
        machine.onPointerEvent(0L, threeFingers(200f))

        // Move 20px: past THREE_FINGER_DRAG_SLOP_PX (8) -> press + move
        val engaged = machine.onPointerEvent(40L, threeFingers(180f))
        val presses = engaged.filterIsInstance<GestureEvent.Click>()
            .filter { it.phase == GestureEvent.Click.Phase.PRESS }
        assertEquals(1, presses.size)
        val moves = engaged.filterIsInstance<GestureEvent.Move>()
        assertTrue(moves.isNotEmpty())
        assertEquals(3, moves.first().fingerCount)
        assertTrue(moves.first().dy < 0f)

        // More movement: just moves, no second press
        val more = machine.onPointerEvent(80L, threeFingers(150f))
        assertTrue(more.none { it is GestureEvent.Click })
        assertTrue(more.any { it is GestureEvent.Move })

        // Lift all: release
        val lift = machine.onPointerEvent(120L, emptyList())
        val releases = lift.filterIsInstance<GestureEvent.Click>()
            .filter { it.phase == GestureEvent.Click.Phase.RELEASE }
        assertEquals(1, releases.size)
    }

    @Test
    fun `three finger drag below slop is cancelled without clicks`() {
        machine.threeFingerDragEnabled = true
        machine.onPointerEvent(0L, threeFingers(200f))
        // 5px < slop (8)
        val small = machine.onPointerEvent(30L, threeFingers(195f))
        assertTrue(small.isEmpty())

        // Lift before engaging: nothing is sent
        val lift = machine.onPointerEvent(60L, emptyList())
        assertTrue(lift.isEmpty())
    }

    @Test
    fun `three finger drag replaces three finger swipe when enabled`() {
        machine.threeFingerDragEnabled = true
        machine.onPointerEvent(0L, threeFingers(200f))
        val e = machine.onPointerEvent(60L, threeFingers(120f))
        assertTrue(e.none { it is GestureEvent.Swipe })
        assertTrue(e.any { it is GestureEvent.Move })
    }

    @Test
    fun `four finger swipe still works while three finger drag is enabled`() {
        machine.threeFingerDragEnabled = true
        val four = { y: Float ->
            listOf(p(1L, 100f, y), p(2L, 200f, y), p(3L, 150f, y + 50f), p(4L, 150f, y - 50f))
        }
        machine.onPointerEvent(0L, four(200f))
        val e = machine.onPointerEvent(50L, four(150f))
        assertEquals(GestureEvent.Swipe(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.UP), e[0])
    }

    @Test
    fun `two finger scroll followed by third finger does not emit momentum`() {
        machine.onPointerEvent(0L, listOf(p(1L, 100f, 100f)))
        machine.onPointerEvent(20L, listOf(p(1L, 100f, 100f), p(2L, 200f, 100f)))
        machine.onPointerEvent(40L, listOf(p(1L, 100f, 130f), p(2L, 200f, 130f)))

        // Third finger lands mid-scroll: multi session begins
        val e = machine.onPointerEvent(60L, threeFingers(130f))
        assertTrue(e.none { it is GestureEvent.Scroll })

        // Everything lifts: no momentum tail, no clicks
        val lift = machine.onPointerEvent(100L, emptyList())
        assertTrue(lift.none { it is GestureEvent.Click })
        assertFalse(machine.isMomentumActive)
    }
}
