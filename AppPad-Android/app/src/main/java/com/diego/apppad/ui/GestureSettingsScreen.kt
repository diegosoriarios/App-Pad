package com.diego.apppad.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diego.apppad.gesture.GestureAction
import com.diego.apppad.gesture.GestureDirection
import com.diego.apppad.gesture.GestureOrigin
import com.diego.apppad.settings.GestureSettings

private val SettingsBackground = Color(0xFF09090A)
private val ChipBackground = Color(0xFF1E1E22)

private fun GestureAction.displayName(): String = when (this) {
    GestureAction.DISABLED -> "Disabled"
    GestureAction.MISSION_CONTROL -> "Mission Control"
    GestureAction.APP_EXPOSE -> "App Expose"
    GestureAction.SPACE_NEXT -> "Next Space"
    GestureAction.SPACE_PREV -> "Previous Space"
    GestureAction.SHOW_DESKTOP -> "Show Desktop"
    GestureAction.LAUNCHPAD -> "Launchpad"
    GestureAction.NOTIFICATION_CENTER -> "Notification Center"
}

private data class SlotRow(val origin: Int, val direction: Int, val label: String)

private val SLOT_ROWS = listOf(
    SlotRow(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.UP, "3-Finger Swipe Up"),
    SlotRow(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.DOWN, "3-Finger Swipe Down"),
    SlotRow(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.LEFT, "3-Finger Swipe Left"),
    SlotRow(GestureOrigin.THREE_FINGER_SWIPE, GestureDirection.RIGHT, "3-Finger Swipe Right"),
    SlotRow(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.UP, "4-Finger Swipe Up"),
    SlotRow(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.DOWN, "4-Finger Swipe Down"),
    SlotRow(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.LEFT, "4-Finger Swipe Left"),
    SlotRow(GestureOrigin.FOUR_FINGER_SWIPE, GestureDirection.RIGHT, "4-Finger Swipe Right")
)

private val ALL_ACTIONS = GestureAction.entries

/** Enable / disable / remap gestures (macOS-style defaults, PROTOCOL.md §8). */
@Composable
fun GestureSettingsScreen(
    settings: GestureSettings,
    onBack: () -> Unit
) {
    BackHandler(onBack = onBack)

    val dragEnabled = settings.threeFingerDrag
    // Read so slot/action changes re-compose the rows below.
    settings.revision

    Surface(modifier = Modifier.fillMaxSize(), color = SettingsBackground) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(top = 40.dp, start = 16.dp, end = 16.dp, bottom = 24.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = onBack) {
                    Text("< Back", color = Color(0xFF0A84FF), fontSize = 14.sp)
                }
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Gestures",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                )
            }
            Spacer(modifier = Modifier.height(8.dp))

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = ChipBackground.copy(alpha = 0.85f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Three-Finger Drag", color = Color.White, fontSize = 14.sp)
                        Text(
                            text = "Move the cursor with three fingers to drag. Replaces 3-finger swipes.",
                            color = Color(0xFF8E8E93),
                            fontSize = 11.sp
                        )
                    }
                    Switch(
                        checked = dragEnabled,
                        onCheckedChange = { settings.threeFingerDrag = it },
                        colors = SwitchDefaults.colors(
                            checkedTrackColor = Color(0xFF4CAF50),
                            uncheckedTrackColor = Color(0xFF3A3A3E)
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Swipe actions",
                style = MaterialTheme.typography.labelMedium.copy(color = Color(0xFF8E8E93)),
                modifier = Modifier.padding(start = 4.dp, bottom = 6.dp)
            )

            for (row in SLOT_ROWS) {
                SlotRowItem(
                    label = row.label,
                    current = settings.action(row.origin, row.direction),
                    onSelect = { settings.setAction(row.origin, row.direction, it) }
                )
                Spacer(modifier = Modifier.height(6.dp))
            }

            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Pinch and rotate are not available system-wide on macOS; " +
                    "a modifier + scroll based pinch-zoom is planned.",
                color = Color(0xFF6E6E73),
                fontSize = 11.sp,
                modifier = Modifier.padding(horizontal = 4.dp)
            )
        }
    }
}

@Composable
private fun SlotRowItem(
    label: String,
    current: GestureAction,
    onSelect: (GestureAction) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = ChipBackground.copy(alpha = 0.85f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 6.dp)
                .clickable { expanded = true },
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = label,
                color = Color.White,
                fontSize = 14.sp,
                modifier = Modifier.weight(1f)
            )
            Box {
                Text(
                    text = current.displayName(),
                    color = if (current == GestureAction.DISABLED) Color(0xFF8E8E93) else Color(0xFF0A84FF),
                    fontSize = 13.sp
                )
                DropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false },
                    modifier = Modifier.background(Color(0xFF2C2C2E))
                ) {
                    for (action in ALL_ACTIONS) {
                        DropdownMenuItem(
                            text = {
                                Text(
                                    text = action.displayName(),
                                    color = if (action == current) Color(0xFF4CAF50) else Color.White,
                                    fontSize = 14.sp
                                )
                            },
                            onClick = {
                                expanded = false
                                onSelect(action)
                            }
                        )
                    }
                }
            }
        }
    }
}
