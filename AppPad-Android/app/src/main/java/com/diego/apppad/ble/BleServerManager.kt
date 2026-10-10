package com.diego.apppad.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Log
import com.diego.apppad.pairing.PairingProtocol
import com.diego.apppad.pairing.PhoneIdentity
import com.diego.apppad.pairing.PhonePairingSession
import com.diego.apppad.pairing.TrustedMac
import com.diego.apppad.pairing.TrustedMacStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CopyOnWriteArrayList

/**
 * GATT server (peripheral) side of AirPad. Owns the secure session:
 *
 *  - The Mac (central) writes control frames to the characteristic; they are
 *    reassembled and fed to [PhonePairingSession].
 *  - Handshake replies and encrypted traffic frames go out as notifications.
 *  - Gesture traffic (15-byte v1 packets) is only sent once the session is
 *    ready, and always encrypted ([PairingProtocol.TrafficCipher], 36-byte
 *    frames — requires the negotiated MTU to be at least 39; macOS centrals
 *    negotiate ~185 automatically).
 */
class BleServerManager(
    private val context: Context,
    identity: PhoneIdentity,
    private val macStore: TrustedMacStore
) {

    companion object {
        private const val TAG = "BleServerManager"
    }

    enum class SessionPhase {
        IDLE,             // not connected
        NEGOTIATING,      // connected, handshake in progress
        READY,            // encrypted session live
        PAIRING_NEEDED,   // Mac rejected us (unknown device / verify failed)
        FAILED            // local handshake error
    }

    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager

    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager?.adapter

    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var touchCharacteristic: BluetoothGattCharacteristic? = null

    private val connectedDevices = CopyOnWriteArrayList<BluetoothDevice>()

    private val session = PhonePairingSession(identity) { macId -> macStore.find(macId) }
    private val defragmenter = PairingProtocol.Defragmenter()

    private val _isAdvertising = MutableStateFlow(false)
    val isAdvertising: StateFlow<Boolean> = _isAdvertising.asStateFlow()

    /** True while the GATT server is open (advertising or connected). */
    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()

    private val _statusMessage = MutableStateFlow("Initializing BLE...")
    val statusMessage: StateFlow<String> = _statusMessage.asStateFlow()

    private val _sessionPhase = MutableStateFlow(SessionPhase.IDLE)
    val sessionPhase: StateFlow<SessionPhase> = _sessionPhase.asStateFlow()

    private val _trustedMacs = MutableStateFlow(macStore.loadAll())
    val trustedMacs: StateFlow<List<TrustedMac>> = _trustedMacs.asStateFlow()

    private val _pairingMacName = MutableStateFlow<String?>(null)
    val pairingMacName: StateFlow<String?> = _pairingMacName.asStateFlow()

    /** True when the user initiated pairing before the Mac connected. */
    private val _isWaitingToPair = MutableStateFlow(false)
    val isWaitingToPair: StateFlow<Boolean> = _isWaitingToPair.asStateFlow()

    /** OTP captured from QR/PIN while offline; flushed once the Mac subscribes. */
    private var pendingPairingOtp: ByteArray? = null

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d(TAG, "BLE Advertising started successfully")
            _isAdvertising.value = true
            _statusMessage.value = "Advertising AirPad Service... Ready to connect."
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "BLE Advertising failed with code: $errorCode")
            _isAdvertising.value = false
            _statusMessage.value = "Advertising failed ($errorCode)"
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            Log.d(TAG, "onConnectionStateChange: device=${device.address}, status=$status, newState=$newState")
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (!connectedDevices.contains(device)) {
                    connectedDevices.add(device)
                }
                _isConnected.value = true
                _statusMessage.value = "Connected to ${device.name ?: device.address}"
                _sessionPhase.value = SessionPhase.NEGOTIATING
                // A pairing started while offline (scan/PIN before connect)
                // is sent as soon as a Mac attaches; if the client has not
                // subscribed to notifications yet the CCCD hook retries.
                trySendPendingPairing()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                connectedDevices.remove(device)
                _isConnected.value = connectedDevices.isNotEmpty()
                _statusMessage.value = if (connectedDevices.isEmpty()) {
                    "Disconnected. Waiting for connection..."
                } else {
                    "Connected to ${connectedDevices.size} device(s)"
                }
                if (connectedDevices.isEmpty()) {
                    _sessionPhase.value = SessionPhase.IDLE
                    _pairingMacName.value = null
                    clearPendingPairing()
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            if (descriptor.uuid == BleConstants.CCCD_UUID) {
                Log.d(TAG, "CCCD updated by ${device.address}")
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                }
                // The Mac is now subscribed to notifications: any pairing
                // captured while offline can be delivered safely.
                trySendPendingPairing()
            }
        }

        @SuppressLint("MissingPermission")
        // Read requests have no responseNeeded parameter; always reply with
        // the current CCCD value so central-side subscription reads succeed.
        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor
        ) {
            if (descriptor.uuid == BleConstants.CCCD_UUID) {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                )
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            if (characteristic.uuid == BleConstants.TOUCH_CHARACTERISTIC_UUID) {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                }
                if (!preparedWrite) {
                    handleControlFrame(value)
                }
            } else if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            super.onServiceAdded(status, service)
            Log.d(TAG, "onServiceAdded: uuid=${service?.uuid}, status=$status")
            if (status == BluetoothGatt.GATT_SUCCESS && service?.uuid == BleConstants.SERVICE_UUID) {
                startAdvertising()
            } else {
                _statusMessage.value = "Failed to register GATT Service ($status)"
            }
        }
    }

    @SuppressLint("MissingPermission")
    fun startServer(): Boolean {
        // Idempotent: a second call (e.g. Activity recreation) must not open a
        // second GATT server on top of the running one.
        if (gattServer != null) {
            Log.d(TAG, "startServer: already running")
            _isRunning.value = true
            return true
        }
        val adapter = bluetoothAdapter
        // isEnabled is false when Bluetooth was toggled off via quick
        // settings on many devices (Samsung et al.), yet the stack stays in
        // the hidden STATE_BLE_ON (value 15) and LE advertising/GATT still
        // work — only bail out when the stack is definitively off.
        val state = adapter?.state ?: BluetoothAdapter.STATE_OFF
        val bleAvailable = adapter != null &&
            (adapter.isEnabled ||
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                    state != BluetoothAdapter.STATE_OFF &&
                    state != BluetoothAdapter.STATE_TURNING_OFF))
        if (!bleAvailable) {
            Log.e(TAG, "startServer: no usable Bluetooth (state=$state)")
            _statusMessage.value = "Bluetooth is disabled — turn it on to use AirPad"
            return false
        }
        Log.d(TAG, "startServer: opening GATT server (state=$state)")

        gattServer = bluetoothManager?.openGattServer(context, gattServerCallback)
        if (gattServer == null) {
            Log.e(TAG, "startServer: openGattServer returned null")
            _statusMessage.value = "Failed to open GATT Server"
            return false
        }

        // Create AirPad Service & Characteristic
        val service = BluetoothGattService(
            BleConstants.SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        touchCharacteristic = BluetoothGattCharacteristic(
            BleConstants.TOUCH_CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or
                BluetoothGattCharacteristic.PROPERTY_NOTIFY or
                BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or
                BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        val cccd = BluetoothGattDescriptor(
            BleConstants.CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        touchCharacteristic?.addDescriptor(cccd)
        service.addCharacteristic(touchCharacteristic)

        val serviceAdded = gattServer?.addService(service) ?: false
        if (!serviceAdded) {
            _statusMessage.value = "Failed to add GATT Service"
            return false
        }

        // Advertising starts asynchronously from onServiceAdded() once the
        // service is actually registered on the local GATT server.
        _statusMessage.value = "Registering GATT Service..."
        _isRunning.value = true
        return true
    }

    @SuppressLint("MissingPermission")
    private fun startAdvertising() {
        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            _statusMessage.value = "BLE Advertiser unavailable on this device"
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()

        // Keep the legacy 31-byte packet small: a 128-bit service UUID plus
        // the device name overflows on many phones, and the UUID then lands
        // in the scan response where macOS's filtered scan can miss it.
        // Manufacturer data ("AP" marker, vendor ID 0xFFFF) identifies us to
        // the Mac even if a ROM drops the UUID entirely.
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(BleConstants.SERVICE_UUID))
            .addManufacturerData(0xFFFF, byteArrayOf(0x41, 0x50))
            .build()

        advertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    @SuppressLint("MissingPermission")
    fun stopServer() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
            _isAdvertising.value = false
            gattServer?.close()
            gattServer = null
            connectedDevices.clear()
            _isConnected.value = false
            _sessionPhase.value = SessionPhase.IDLE
            _isRunning.value = false
            _statusMessage.value = "Trackpad stopped — tap Start trackpad to go back online"
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping BLE Server", e)
        }
    }

    // MARK: - Pairing actions (called from the UI)

    /** Starts phone-initiated pairing with the OTP from a scanned QR code. */
    fun startPairingWithQr(qrText: String): Boolean {
        val offer = PairingProtocol.decodeOfferQR(qrText)
        if (offer == null) {
            _statusMessage.value = "Not an AirPad QR code"
            return false
        }
        _pairingMacName.value = offer.macName
        return sendPairingRequest(offer.otp)
    }

    /** Starts phone-initiated pairing with the PIN shown under the Mac's QR. */
    fun startPairingWithPin(pin: String, macName: String?): Boolean {
        _pairingMacName.value = macName
        return sendPairingRequest(PairingProtocol.otpFromPin(pin))
    }

    /**
     * Sends the pairing request now, or parks the OTP until the Mac connects
     * and subscribes (the phone cannot initiate a BLE connection itself).
     */
    private fun sendPairingRequest(otp: ByteArray): Boolean {
        if (connectedDevices.isEmpty()) {
            pendingPairingOtp = otp
            _isWaitingToPair.value = true
            _statusMessage.value = "Waiting for Mac — pairing starts automatically once it connects"
            return true
        }
        return sendPairingRequestNow(otp)
    }

    private fun trySendPendingPairing() {
        val otp = pendingPairingOtp ?: return
        if (connectedDevices.isEmpty()) return
        pendingPairingOtp = null
        _isWaitingToPair.value = false
        sendPairingRequestNow(otp)
    }

    private fun clearPendingPairing() {
        pendingPairingOtp = null
        _isWaitingToPair.value = false
    }

    @SuppressLint("MissingPermission")
    private fun sendPairingRequestNow(otp: ByteArray): Boolean {
        if (connectedDevices.isEmpty()) {
            _statusMessage.value = "Not connected to a Mac yet"
            return false
        }
        _sessionPhase.value = SessionPhase.NEGOTIATING
        for (message in session.startPairing(otp)) {
            notifyControl(message.type, message.payload)
        }
        return true
    }

    fun removeMac(mac: TrustedMac) {
        macStore.remove(mac.macId)
        _trustedMacs.value = macStore.loadAll()
    }

    // MARK: - Control path (handshake)

    @SuppressLint("MissingPermission")
    private fun handleControlFrame(frame: ByteArray) {
        val message = defragmenter.feed(frame) ?: return
        _sessionPhase.value = SessionPhase.NEGOTIATING
        val result = session.onMessage(message.type, message.payload)

        for (out in result.messages) {
            notifyControl(out.type, out.payload)
        }
        for (event in result.events) {
            when (event) {
                is PhonePairingSession.Event.MacPaired -> {
                    macStore.add(event.mac)
                    _trustedMacs.value = macStore.loadAll()
                }
                is PhonePairingSession.Event.Ready -> {
                    _sessionPhase.value = SessionPhase.READY
                    _statusMessage.value = "Secure session active"
                }
                is PhonePairingSession.Event.Failed -> {
                    _sessionPhase.value = SessionPhase.FAILED
                    _statusMessage.value = "Pairing failed: ${event.reason}"
                }
                is PhonePairingSession.Event.MacError -> {
                    // unknownDevice / verifyFailed -> offer QR/PIN pairing.
                    _sessionPhase.value = SessionPhase.PAIRING_NEEDED
                    _statusMessage.value = "Pair with the Mac via QR or PIN"
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun notifyControl(type: Byte, payload: ByteArray) {
        for (frame in PairingProtocol.chunkMessage(type, payload)) {
            notifyRaw(frame)
        }
    }

    // MARK: - Gesture traffic (encrypted)

    fun sendMove(dx: Float, dy: Float, fingerCount: Int = 1) {
        sendPacket(headerBuffer(BleConstants.PACKET_TYPE_MOVE, fingerCount, dx, dy).array())
    }

    fun sendScroll(dx: Float, dy: Float, fingerCount: Int = 2) {
        sendPacket(headerBuffer(BleConstants.PACKET_TYPE_SCROLL, fingerCount, dx, dy).array())
    }

    fun sendClick(button: Int, pressed: Boolean) {
        val packet = ByteArray(15)
        packet[0] = BleConstants.PROTOCOL_VERSION
        packet[1] = BleConstants.PACKET_TYPE_CLICK
        packet[2] = button.toByte()
        packet[3] = if (pressed) BleConstants.PHASE_PRESS else BleConstants.PHASE_RELEASE
        ByteBuffer.wrap(packet).apply {
            order(ByteOrder.LITTLE_ENDIAN)
            position(4)
            putInt(currentTimestamp())
        }
        sendPacket(packet)
    }

    /** Gesture event (PROTOCOL.md §8, packet 0x04): action, origin, direction. */
    fun sendGesture(actionCode: Int, origin: Int, direction: Int) {
        val packet = ByteArray(15)
        packet[0] = BleConstants.PROTOCOL_VERSION
        packet[1] = BleConstants.PACKET_TYPE_GESTURE
        packet[2] = actionCode.toByte()
        packet[3] = origin.toByte()
        packet[4] = direction.toByte()
        ByteBuffer.wrap(packet).apply {
            order(ByteOrder.LITTLE_ENDIAN)
            position(5)
            putInt(currentTimestamp())
        }
        sendPacket(packet)
    }

    private fun sendPacket(v1Packet: ByteArray) {
        if (connectedDevices.isEmpty()) return
        val frame = session.encryptV1(v1Packet) ?: run {
            // No secure session yet: silently drop traffic (UI shows the state).
            return
        }
        notifyRaw(frame)
    }

    private fun headerBuffer(type: Byte, fingerCount: Int, dx: Float, dy: Float): ByteBuffer =
        ByteBuffer.allocate(15).apply {
            order(ByteOrder.LITTLE_ENDIAN)
            put(BleConstants.PROTOCOL_VERSION)
            put(type)
            put(fingerCount.toByte())
            putInt(currentTimestamp())
            putFloat(dx)
            putFloat(dy)
        }

    private fun currentTimestamp(): Int = (SystemClock.uptimeMillis() and 0xFFFFFFFFL).toInt()

    @SuppressLint("MissingPermission")
    private fun notifyRaw(frame: ByteArray) {
        if (connectedDevices.isEmpty()) return
        val char = touchCharacteristic ?: return
        val server = gattServer ?: return

        for (device in connectedDevices) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val status = server.notifyCharacteristicChanged(device, char, false, frame)
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    Log.w(TAG, "notify failed (${frame.size}B): status=$status — MTU too small?")
                }
            } else {
                @Suppress("DEPRECATION")
                char.value = frame
                @Suppress("DEPRECATION")
                server.notifyCharacteristicChanged(device, char, false)
            }
        }
    }
}
