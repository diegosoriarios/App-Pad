package com.diego.apppad

import android.app.Application
import com.diego.apppad.ble.BleServerManager
import com.diego.apppad.haptics.HapticPlayer
import com.diego.apppad.pairing.PhoneIdentity
import com.diego.apppad.pairing.TrustedMacStore
import com.diego.apppad.settings.GestureSettings
import com.diego.apppad.settings.TrackpadSettings

/**
 * App-scoped singletons. The BLE stack and user settings must outlive
 * Activity recreations (rotation, theme change) — recreating
 * [BleServerManager] per Activity would tear down the GATT server and drop
 * the Mac connection on every rotate.
 */
class AirPadApp : Application() {

    lateinit var bleServerManager: BleServerManager
        private set
    lateinit var settings: TrackpadSettings
        private set
    lateinit var gestureSettings: GestureSettings
        private set
    lateinit var hapticPlayer: HapticPlayer
        private set

    override fun onCreate() {
        super.onCreate()
        val identity = PhoneIdentity.load(this)
        val macStore = TrustedMacStore(this)
        bleServerManager = BleServerManager(this, identity, macStore)
        settings = TrackpadSettings(this)
        gestureSettings = GestureSettings(this)
        hapticPlayer = HapticPlayer(this, settings)
    }
}
