package com.diego.apppad.gesture

import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.pow

/** Immutable snapshot of one active touch contact, in screen pixels. */
data class TouchPoint(val id: Long, val x: Float, val y: Float)

/** Events emitted by [TouchStateMachine] for the transport and haptics layers. */
sealed class GestureEvent {
    /** One-finger cursor movement, already accelerated. */
    data class Move(val dx: Float, val dy: Float, val fingerCount: Int = 1) : GestureEvent()

    /** Two-finger scroll delta, in raw finger-travel direction. */
    data class Scroll(val dx: Float, val dy: Float, val isMomentum: Boolean) : GestureEvent()

    /** Button click (tap-to-click, two-finger tap, drag press/release). */
    data class Click(val button: Button, val phase: Phase) : GestureEvent() {
        enum class Button { LEFT, RIGHT }
        enum class Phase { PRESS, RELEASE }
    }

    /**
     * Discrete three/four-finger swipe, fired once per contact session when
     * the centroid travel passes the activation threshold along the dominant
     * axis. [origin] is a [GestureOrigin] code, [direction] a
     * [GestureDirection] code.
     */
    data class Swipe(val origin: Int, val direction: Int) : GestureEvent()
}

/**
 * Pointer-acceleration curve for cursor movement: gain grows linearly with
 * finger speed up to [PointerAccelerator.Config.MAX_GAIN].
 */
class PointerAccelerator {
    object Config {
        const val REFERENCE_SPEED_PX_PER_MS = 0.9f
        const val MIN_GAIN = 1.0f
        const val MAX_GAIN = 2.4f
    }

    fun apply(dx: Float, dy: Float, speedPxPerMs: Float): Pair<Float, Float> {
        val gain = (Config.MIN_GAIN + speedPxPerMs / Config.REFERENCE_SPEED_PX_PER_MS)
            .coerceIn(Config.MIN_GAIN, Config.MAX_GAIN)
        return dx * gain to dy * gain
    }

    fun reset() = Unit
}

/**
 * Pure-Kotlin gesture recognizer for the trackpad surface.
 *
 * Feed full pointer snapshots via [onPointerEvent] (one call per pointer
 * event) and drive inertia after finger lift via [onTick]. All methods take
 * an external millisecond clock so the class is fully unit-testable and free
 * of Android dependencies.
 *
 * Supported gestures:
 *  - 1-finger move  -> [GestureEvent.Move] (accelerated)
 *  - 1-finger tap   -> left click press + release
 *  - tap, then new touch + move -> click and drag (press, moves, release on lift)
 *  - 2-finger tap   -> right click press + release
 *  - 2-finger move  -> [GestureEvent.Scroll], with momentum after lift
 *  - 3/4-finger move -> [GestureEvent.Swipe] once past the activation threshold
 *  - 3-finger move with [threeFingerDragEnabled] -> click-drag (press/moves/release)
 */
class TouchStateMachine(private val accelerator: PointerAccelerator = PointerAccelerator()) {

    /** Named gesture thresholds — tune here only. */
    object Config {
        /** Max duration of a contact for it to count as a tap. */
        const val TAP_TIMEOUT_MS = 180L

        /** Max accumulated movement (px) during a contact for it to count as a tap. */
        const val TAP_SLOP_PX = 24f

        /** Max time from second-finger-down to both fingers lifted for a two-finger tap. */
        const val TWO_FINGER_WINDOW_MS = 280L

        /** Centroid travel (px) required before a two-finger touch becomes a scroll. */
        const val SCROLL_RAMP_PX = 14f

        /** Scroll delta gain applied to raw finger travel. */
        const val SCROLL_GAIN = 1.0f

        /** Movement (px) after a tap required to turn the next touch into a drag. */
        const val DRAG_SLOP_PX = 12f

        /** Max gap between a tap release and the next touch for tap-drag to engage. */
        const val TAP_DRAG_TIMEOUT_MS = 350L

        /** Fraction of scroll velocity retained per momentum tick. */
        const val MOMENTUM_DECAY = 0.90f

        /** Nominal momentum tick length (ms) — ~60 Hz. */
        const val MOMENTUM_TICK_MS = 16L

        /** Momentum stops when speed drops below this (px per tick). */
        const val MOMENTUM_STOP_PX_PER_TICK = 0.08f

        /** EMA weight of the newest velocity sample (0..1). */
        const val VELOCITY_SMOOTHING = 0.35f

        /** Centroid travel (px) required to fire a three/four-finger swipe. */
        const val SWIPE_ACTIVATE_PX = 30f

        /** Movement (px) before three-finger drag engages (still cancellable). */
        const val THREE_FINGER_DRAG_SLOP_PX = 8f
    }

    private enum class State { IDLE, SINGLE_DOWN, TWO_DOWN, WAIT_ALL_UP, MOMENTUM, MULTI_DOWN }

    var isMomentumActive: Boolean = false
        private set

    /**
     * When true, three-finger contact + movement becomes a click-drag
     * (press, accelerated moves with fingerCount = 3, release on lift)
     * instead of a three-finger swipe. Four-finger swipes are unaffected.
     */
    var threeFingerDragEnabled: Boolean = false

    private var state = State.IDLE
    private var points: Map<Long, TouchPoint> = emptyMap()
    private var lastEventTimeMs = 0L

    private var primaryId: Long = -1L
    private var downTimeMs = 0L
    private var totalMovementPx = 0f
    private var lastPrimary: TouchPoint? = null

    private var twoFingerStartMs = 0L
    private var twoFingerMovementPx = 0f
    private var lastCentroid: TouchPoint? = null
    private var scrollVelocityX = 0f
    private var scrollVelocityY = 0f

    private var lastGestureWasTap = false
    private var lastTapEndMs = 0L
    private var dragging = false

    private var lastTickMs = 0L

    private var multiStartCentroid: TouchPoint? = null
    private var multiLastCentroid: TouchPoint? = null
    private var multiSwipeFired = false
    private var multiDragEngaged = false

    /**
     * Feed one pointer event. [snapshot] must contain every currently pressed
     * contact (an empty list means all fingers lifted).
     */
    fun onPointerEvent(nowMs: Long, snapshot: List<TouchPoint>): List<GestureEvent> {
        val events = mutableListOf<GestureEvent>()
        val current = snapshot.associateBy { it.id }
        val downIds = current.keys - points.keys
        val dtMs = (nowMs - lastEventTimeMs).coerceIn(1L, 200L)
        lastEventTimeMs = nowMs

        if (downIds.isNotEmpty() && isMomentumActive) stopMomentum()

        // Three or more fingers take over the session entirely: swipes or
        // (optionally) three-finger drag. Move/scroll/tap logic is suppressed.
        if (current.size >= 3) {
            if (state != State.MULTI_DOWN) beginMultiDown(nowMs, current, events)
            trackMultiFingerMove(nowMs, dtMs, current, events)
            points = current
            return events
        }
        if (state == State.MULTI_DOWN) {
            // Fingers dropped below three: finish the multi-finger session
            // and ignore any straggler until all contacts are gone.
            endMultiDown(events)
            state = if (current.isEmpty()) State.IDLE else State.WAIT_ALL_UP
            points = current
            return events
        }

        when (state) {
            State.IDLE, State.MOMENTUM -> beginSingleDown(nowMs, current)

            State.SINGLE_DOWN -> when {
                current.isEmpty() -> endSingleFinger(nowMs, events)
                current.size >= 2 -> beginTwoDown(nowMs, current)
                else -> trackSingleMove(nowMs, dtMs, current, events)
            }

            State.TWO_DOWN -> when {
                current.isEmpty() -> endTwoFingerSession(nowMs, events)
                current.size >= 2 -> trackTwoFingerMove(nowMs, dtMs, current, events)
                else -> {
                    // One finger lifted but a straggler remains: finish the
                    // two-finger session and ignore the straggler until all
                    // contacts are gone.
                    endTwoFingerSession(nowMs, events)
                    if (state == State.IDLE) state = State.WAIT_ALL_UP
                }
            }

            State.WAIT_ALL_UP -> when {
                downIds.isNotEmpty() -> beginSingleDown(nowMs, current)
                current.isEmpty() -> state = State.IDLE
            }

            // Handled by the multi-finger early-exit above; unreachable here.
            State.MULTI_DOWN -> Unit
        }

        points = current
        return events
    }

    /**
     * Advance momentum inertia; call at ~60 Hz between gesture sessions.
     * Returns scroll events while momentum is running.
     */
    fun onTick(nowMs: Long): List<GestureEvent> {
        if (!isMomentumActive) return emptyList()
        val dtMs = (nowMs - lastTickMs).coerceIn(1L, 100L)
        lastTickMs = nowMs
        val decay = Config.MOMENTUM_DECAY.pow(dtMs.toFloat() / Config.MOMENTUM_TICK_MS)
        scrollVelocityX *= decay
        scrollVelocityY *= decay
        if (hypot(scrollVelocityX, scrollVelocityY) < Config.MOMENTUM_STOP_PX_PER_TICK) {
            stopMomentum()
            return emptyList()
        }
        return listOf(GestureEvent.Scroll(scrollVelocityX, scrollVelocityY, isMomentum = true))
    }

    /** Force-reset to idle (e.g. connection lost, screen hidden). */
    fun cancel() {
        stopMomentum()
        state = State.IDLE
        points = emptyMap()
        lastPrimary = null
        lastCentroid = null
        dragging = false
        lastGestureWasTap = false
        totalMovementPx = 0f
        twoFingerMovementPx = 0f
        multiStartCentroid = null
        multiLastCentroid = null
        multiSwipeFired = false
        multiDragEngaged = false
    }

    private fun beginSingleDown(nowMs: Long, current: Map<Long, TouchPoint>) {
        if (current.isEmpty()) return
        stopMomentum()
        state = State.SINGLE_DOWN
        primaryId = current.keys.first()
        downTimeMs = nowMs
        totalMovementPx = 0f
        lastPrimary = current.values.first()
        accelerator.reset()
    }

    private fun trackSingleMove(
        nowMs: Long,
        dtMs: Long,
        current: Map<Long, TouchPoint>,
        events: MutableList<GestureEvent>
    ) {
        val primary = current[primaryId] ?: current.values.first()
        val last = lastPrimary ?: return
        val dx = primary.x - last.x
        val dy = primary.y - last.y
        lastPrimary = primary
        val moved = hypot(dx, dy)
        totalMovementPx += moved

        // A touch that starts shortly after a tap and travels past the drag
        // slop is a click-and-drag: hold the left button down while moving.
        if (!dragging &&
            lastGestureWasTap &&
            nowMs - lastTapEndMs <= Config.TAP_DRAG_TIMEOUT_MS &&
            totalMovementPx > Config.DRAG_SLOP_PX
        ) {
            dragging = true
            lastGestureWasTap = false
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.PRESS))
        }

        if (dragging || totalMovementPx > Config.TAP_SLOP_PX) {
            val (ax, ay) = accelerator.apply(dx, dy, moved / dtMs)
            events.add(GestureEvent.Move(ax, ay))
        }
    }

    private fun endSingleFinger(nowMs: Long, events: MutableList<GestureEvent>) {
        if (dragging) {
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.RELEASE))
            dragging = false
            lastGestureWasTap = false
        } else if (nowMs - downTimeMs <= Config.TAP_TIMEOUT_MS && totalMovementPx <= Config.TAP_SLOP_PX) {
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.PRESS))
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.RELEASE))
            lastGestureWasTap = true
            lastTapEndMs = nowMs
        } else {
            lastGestureWasTap = false
        }
        state = State.IDLE
    }

    private fun beginTwoDown(nowMs: Long, current: Map<Long, TouchPoint>) {
        state = State.TWO_DOWN
        twoFingerStartMs = nowMs
        twoFingerMovementPx = 0f
        lastCentroid = centroid(current)
        scrollVelocityX = 0f
        scrollVelocityY = 0f
    }

    private fun trackTwoFingerMove(
        nowMs: Long,
        dtMs: Long,
        current: Map<Long, TouchPoint>,
        events: MutableList<GestureEvent>
    ) {
        val c = centroid(current)
        val last = lastCentroid ?: return
        val dx = c.x - last.x
        val dy = c.y - last.y
        lastCentroid = c
        twoFingerMovementPx += hypot(dx, dy)

        if (twoFingerMovementPx > Config.SCROLL_RAMP_PX) {
            // Velocity is tracked in px per momentum tick for inertia.
            val sampleVx = dx / dtMs * Config.MOMENTUM_TICK_MS
            val sampleVy = dy / dtMs * Config.MOMENTUM_TICK_MS
            scrollVelocityX += (sampleVx - scrollVelocityX) * Config.VELOCITY_SMOOTHING
            scrollVelocityY += (sampleVy - scrollVelocityY) * Config.VELOCITY_SMOOTHING
            events.add(GestureEvent.Scroll(dx * Config.SCROLL_GAIN, dy * Config.SCROLL_GAIN, isMomentum = false))
        }
    }

    private fun endTwoFingerSession(nowMs: Long, events: MutableList<GestureEvent>) {
        val elapsed = nowMs - twoFingerStartMs
        if (elapsed <= Config.TWO_FINGER_WINDOW_MS && twoFingerMovementPx <= Config.TAP_SLOP_PX) {
            events.add(GestureEvent.Click(GestureEvent.Click.Button.RIGHT, GestureEvent.Click.Phase.PRESS))
            events.add(GestureEvent.Click(GestureEvent.Click.Button.RIGHT, GestureEvent.Click.Phase.RELEASE))
            state = State.IDLE
        } else if (hypot(scrollVelocityX, scrollVelocityY) > Config.MOMENTUM_STOP_PX_PER_TICK) {
            state = State.MOMENTUM
            isMomentumActive = true
            lastTickMs = nowMs
        } else {
            state = State.IDLE
        }
        lastGestureWasTap = false
    }

    private fun stopMomentum() {
        isMomentumActive = false
        scrollVelocityX = 0f
        scrollVelocityY = 0f
    }

    // MARK: - Three/four-finger gestures

    private fun beginMultiDown(nowMs: Long, current: Map<Long, TouchPoint>, events: MutableList<GestureEvent>) {
        stopMomentum()
        // A click-drag in progress when extra fingers land must not leave
        // the Mac with a stuck button.
        if (dragging) {
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.RELEASE))
            dragging = false
            lastGestureWasTap = false
        }
        val c = centroid(current)
        multiStartCentroid = c
        multiLastCentroid = c
        multiSwipeFired = false
        multiDragEngaged = false
        state = State.MULTI_DOWN
    }

    private fun trackMultiFingerMove(
        nowMs: Long,
        dtMs: Long,
        current: Map<Long, TouchPoint>,
        events: MutableList<GestureEvent>
    ) {
        val start = multiStartCentroid ?: return
        val prev = multiLastCentroid ?: return
        val c = centroid(current)
        val dx = c.x - prev.x
        val dy = c.y - prev.y
        multiLastCentroid = c
        val dispX = c.x - start.x
        val dispY = c.y - start.y

        // Three-finger drag: engages after slop, then streams accelerated
        // centroid moves behind a held left button (like the one-finger
        // click-and-drag path). Replaces three-finger swipes while enabled.
        if (!multiDragEngaged && !multiSwipeFired &&
            threeFingerDragEnabled &&
            current.size == 3 &&
            hypot(dispX, dispY) > Config.THREE_FINGER_DRAG_SLOP_PX
        ) {
            multiDragEngaged = true
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.PRESS))
        }

        if (multiDragEngaged) {
            val (ax, ay) = accelerator.apply(dx, dy, hypot(dx, dy) / dtMs)
            events.add(GestureEvent.Move(ax, ay, current.size))
            return
        }

        if (!multiSwipeFired) {
            val adx = abs(dispX)
            val ady = abs(dispY)
            if (maxOf(adx, ady) > Config.SWIPE_ACTIVATE_PX) {
                val direction = if (adx >= ady) {
                    if (dispX < 0) GestureDirection.LEFT else GestureDirection.RIGHT
                } else {
                    if (dispY < 0) GestureDirection.UP else GestureDirection.DOWN
                }
                val origin = if (current.size >= 4) {
                    GestureOrigin.FOUR_FINGER_SWIPE
                } else {
                    GestureOrigin.THREE_FINGER_SWIPE
                }
                multiSwipeFired = true
                events.add(GestureEvent.Swipe(origin, direction))
            }
        }
    }

    private fun endMultiDown(events: MutableList<GestureEvent>) {
        if (multiDragEngaged) {
            events.add(GestureEvent.Click(GestureEvent.Click.Button.LEFT, GestureEvent.Click.Phase.RELEASE))
        }
        multiDragEngaged = false
        multiSwipeFired = false
        multiStartCentroid = null
        multiLastCentroid = null
    }

    private fun centroid(current: Map<Long, TouchPoint>): TouchPoint {
        val values = current.values
        var x = 0f
        var y = 0f
        for (p in values) {
            x += p.x
            y += p.y
        }
        return TouchPoint(id = -1L, x = x / values.size, y = y / values.size)
    }
}
