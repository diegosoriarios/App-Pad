package com.diego.apppad.ble

import java.util.UUID

object BleConstants {
    val SERVICE_UUID: UUID = UUID.fromString("9A3B0001-1234-4567-89AB-CDEF01234567")
    val TOUCH_CHARACTERISTIC_UUID: UUID = UUID.fromString("9A3B0002-1234-4567-89AB-CDEF01234567")
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    const val PROTOCOL_VERSION: Byte = 0x01

    // Packet types (protocol v1.1 + v2 gesture, additive)
    const val PACKET_TYPE_MOVE: Byte = 0x01
    const val PACKET_TYPE_CLICK: Byte = 0x02
    const val PACKET_TYPE_SCROLL: Byte = 0x03
    const val PACKET_TYPE_GESTURE: Byte = 0x04

    // CLICK packet payload values
    const val BUTTON_LEFT: Int = 0x00
    const val BUTTON_RIGHT: Int = 0x01
    const val PHASE_PRESS: Byte = 0x00
    const val PHASE_RELEASE: Byte = 0x01
}
