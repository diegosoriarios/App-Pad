package com.diego.apppad.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diego.apppad.ble.BleConstants
import com.diego.apppad.ble.BleServerManager
import com.diego.apppad.gesture.GestureAction
import com.diego.apppad.gesture.GestureEvent
import com.diego.apppad.gesture.TouchPoint
import com.diego.apppad.gesture.TouchStateMachine
import com.diego.apppad.haptics.HapticPlayer
import com.diego.apppad.settings.GestureSettings
import com.diego.apppad.settings.TrackpadSettings
import kotlinx.coroutines.delay
import android.os.SystemClock

private val TrackpadBackground = Color(0xFF09090A)
private val ChipBackground = Color(0xFF1E1E22)

@Composable
fun TrackpadScreen(
    bleServerManager: BleServerManager,
    hapticPlayer: HapticPlayer,
    settings: TrackpadSettings,
    gestureSettings: GestureSettings,
    onOpenGestureSettings: () -> Unit
) {
    val isAdvertising by bleServerManager.isAdvertising.collectAsState()
    val isConnected by bleServerManager.isConnected.collectAsState()
    val isRunning by bleServerManager.isRunning.collectAsState()
    val statusMessage by bleServerManager.statusMessage.collectAsState()

    val naturalScroll = settings.naturalScroll
    val hapticsEnabled = settings.hapticsEnabled
    val hapticIntensity = settings.hapticIntensity

    val view = LocalView.current
    LaunchedEffect(view) { hapticPlayer.attachView(view) }

    // A trackpad nobody can touch is useless: keep the screen awake while a
    // Mac is connected, release it the moment the session drops.
    DisposableEffect(view, isConnected) {
        view.keepScreenOn = isConnected
        onDispose { view.keepScreenOn = false }
    }

    val machine = remember { TouchStateMachine() }

    fun handleEvents(events: List<GestureEvent>) {
        machine.threeFingerDragEnabled = gestureSettings.threeFingerDrag
        for (event in events) {
            when (event) {
                is GestureEvent.Move ->
                    bleServerManager.sendMove(event.dx, event.dy, event.fingerCount)

                is GestureEvent.Scroll -> {
                    // Read at invocation time so toggles apply without re-capturing
                    val sign = if (settings.naturalScroll) -1f else 1f
                    bleServerManager.sendScroll(event.dx * sign, event.dy * sign)
                }

                is GestureEvent.Click -> {
                    bleServerManager.sendClick(
                        button = if (event.button == GestureEvent.Click.Button.LEFT) {
                            BleConstants.BUTTON_LEFT
                        } else {
                            BleConstants.BUTTON_RIGHT
                        },
                        pressed = event.phase == GestureEvent.Click.Phase.PRESS
                    )
                    if (event.phase == GestureEvent.Click.Phase.PRESS) {
                        hapticPlayer.click()
                    } else {
                        hapticPlayer.tick()
                    }
                }

                is GestureEvent.Swipe -> {
                    val action = gestureSettings.action(event.origin, event.direction)
                    if (action != GestureAction.DISABLED) {
                        bleServerManager.sendGesture(action.code, event.origin, event.direction)
                        hapticPlayer.tick()
                    }
                }
            }
        }
    }

    // Momentum ticker: drives inertia frames after the fingers lift (~60 Hz).
    LaunchedEffect(Unit) {
        while (true) {
            if (machine.isMomentumActive) {
                handleEvents(machine.onTick(SystemClock.uptimeMillis()))
            }
            delay(16)
        }
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = TrackpadBackground // Near-black OLED friendly
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            // Full-screen multi-touch surface feeding the gesture state machine
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(Unit) {
                        awaitEachGesture {
                            val down = awaitFirstDown(requireUnconsumed = false)
                            handleEvents(
                                machine.onPointerEvent(
                                    down.uptimeMillis,
                                    listOf(TouchPoint(down.id.value, down.position.x, down.position.y))
                                )
                            )
                            while (true) {
                                val event = awaitPointerEvent()
                                val pressed = event.changes.filter { it.pressed }
                                val now = event.changes.first().uptimeMillis
                                handleEvents(
                                    machine.onPointerEvent(
                                        now,
                                        pressed.map { TouchPoint(it.id.value, it.position.x, it.position.y) }
                                    )
                                )
                                if (pressed.isEmpty()) break
                            }
                        }
                    }
            )

            // Top status banner
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 40.dp, start = 16.dp, end = 16.dp)
                    .align(Alignment.TopCenter)
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = ChipBackground.copy(alpha = 0.85f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "AirPad Trackpad",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = statusMessage,
                            style = MaterialTheme.typography.bodySmall.copy(
                                color = if (isConnected) Color(0xFF4CAF50) else Color(0xFFFFB74D),
                                fontSize = 12.sp
                            )
                        )
                        // Full stop/start: disconnecting also stops advertising,
                        // otherwise the Mac would auto-reconnect within seconds.
                        TextButton(
                            onClick = {
                                if (isRunning) bleServerManager.stopServer()
                                else bleServerManager.startServer()
                            }
                        ) {
                            Text(
                                text = if (isRunning) "Disconnect" else "Start trackpad",
                                color = if (isRunning) Color(0xFFFF453A) else Color(0xFF0A84FF),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                PairingPanel(bleServerManager = bleServerManager)
            }

            // Bottom controls: gesture hint + inline settings (full settings screen in Step 4)
            Column(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 24.dp, start = 16.dp, end = 16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "1 finger move · tap click · 2 fingers scroll / right-click · tap + move drag · 3/4-finger swipe actions",
                    style = MaterialTheme.typography.labelSmall.copy(
                        color = Color(0xFF6E6E73),
                        fontSize = 11.sp
                    )
                )
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = ChipBackground.copy(alpha = 0.85f)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Column {
                            Text(text = "Natural", color = Color.White, fontSize = 12.sp)
                            Switch(
                                checked = naturalScroll,
                                onCheckedChange = { settings.naturalScroll = it },
                                colors = SwitchDefaults.colors(
                                    checkedTrackColor = Color(0xFF4CAF50),
                                    uncheckedTrackColor = Color(0xFF3A3A3E)
                                )
                            )
                        }
                        Column {
                            Text(text = "Haptics", color = Color.White, fontSize = 12.sp)
                            Switch(
                                checked = hapticsEnabled,
                                onCheckedChange = { settings.hapticsEnabled = it },
                                colors = SwitchDefaults.colors(
                                    checkedTrackColor = Color(0xFF4CAF50),
                                    uncheckedTrackColor = Color(0xFF3A3A3E)
                                )
                            )
                        }
                        Column(modifier = Modifier.width(110.dp)) {
                            Text(
                                text = "Intensity ${(hapticIntensity * 100).toInt()}%",
                                color = Color.White,
                                fontSize = 12.sp
                            )
                            Slider(
                                value = hapticIntensity,
                                onValueChange = { settings.hapticIntensity = it },
                                enabled = hapticsEnabled
                            )
                        }
                    }
                }
                TextButton(onClick = onOpenGestureSettings) {
                    Text(
                        text = "Gestures",
                        color = Color(0xFF0A84FF),
                        fontSize = 12.sp
                    )
                }
                if (isAdvertising && !isConnected) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Waiting for Mac…",
                        color = Color(0xFFFFB74D),
                        fontSize = 11.sp
                    )
                }
            }
        }
    }
}
