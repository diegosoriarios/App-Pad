package com.diego.apppad

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.diego.apppad.ui.GestureSettingsScreen
import com.diego.apppad.ui.PermissionsWrapper
import com.diego.apppad.ui.TrackpadScreen
import com.diego.apppad.ui.theme.AppPadTheme

class MainActivity : ComponentActivity() {

    private val app: AirPadApp by lazy { application as AirPadApp }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            AppPadTheme {
                var showGestureSettings by remember { mutableStateOf(false) }
                PermissionsWrapper(
                    onPermissionsGranted = {
                        app.bleServerManager.startServer()
                    }
                ) {
                    if (showGestureSettings) {
                        GestureSettingsScreen(
                            settings = app.gestureSettings,
                            onBack = { showGestureSettings = false }
                        )
                    } else {
                        TrackpadScreen(
                            bleServerManager = app.bleServerManager,
                            hapticPlayer = app.hapticPlayer,
                            settings = app.settings,
                            gestureSettings = app.gestureSettings,
                            onOpenGestureSettings = { showGestureSettings = true }
                        )
                    }
                }
            }
        }
    }
}
