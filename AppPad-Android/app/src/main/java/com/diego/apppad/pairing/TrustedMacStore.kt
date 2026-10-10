package com.diego.apppad.pairing

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** A Mac this phone trusts after pairing. */
data class TrustedMac(
    val macId: ByteArray,
    val name: String,
    val publicKeyX963: ByteArray,
    val addedAtMillis: Long
) {
    override fun equals(other: Any?): Boolean =
        other is TrustedMac &&
            macId.contentEquals(other.macId) &&
            name == other.name &&
            publicKeyX963.contentEquals(other.publicKeyX963) &&
            addedAtMillis == other.addedAtMillis

    override fun hashCode(): Int =
        macId.contentHashCode() * 31 + name.hashCode() + publicKeyX963.contentHashCode() * 7 + addedAtMillis.hashCode()
}

/**
 * JSON file store for paired Macs (`filesDir/trusted_macs.json`).
 * Mirrors the Mac's `TrustedDeviceStore`.
 */
class TrustedMacStore(context: Context) {

    private val file = File(context.filesDir, "trusted_macs.json")
    private val lock = Any()

    fun loadAll(): List<TrustedMac> = synchronized(lock) { read() }

    fun find(macId: ByteArray): TrustedMac? = loadAll().firstOrNull { it.macId.contentEquals(macId) }

    fun add(mac: TrustedMac) = synchronized(lock) {
        val devices = read().filterNot { it.macId.contentEquals(mac.macId) }.toMutableList()
        devices.add(mac)
        write(devices)
    }

    fun remove(macId: ByteArray) = synchronized(lock) {
        write(read().filterNot { it.macId.contentEquals(macId) })
    }

    private fun read(): List<TrustedMac> = try {
        if (!file.exists()) {
            emptyList()
        } else {
            val array = JSONArray(file.readText())
            (0 until array.length()).mapNotNull { i ->
                val o = array.getJSONObject(i)
                val macId = Base64.decode(o.getString("macId"), Base64.NO_WRAP)
                val key = Base64.decode(o.getString("publicKey"), Base64.NO_WRAP)
                if (macId.size != PairingProtocol.DEVICE_ID_LENGTH ||
                    key.size != PairingProtocol.PUBLIC_KEY_LENGTH
                ) {
                    null
                } else {
                    TrustedMac(macId, o.getString("name"), key, o.getLong("addedAt"))
                }
            }
        }
    } catch (e: Exception) {
        emptyList()
    }

    private fun write(devices: List<TrustedMac>) {
        val array = JSONArray()
        for (device in devices) {
            array.put(
                JSONObject()
                    .put("macId", Base64.encodeToString(device.macId, Base64.NO_WRAP))
                    .put("name", device.name)
                    .put("publicKey", Base64.encodeToString(device.publicKeyX963, Base64.NO_WRAP))
                    .put("addedAt", device.addedAtMillis)
            )
        }
        file.writeText(array.toString())
    }
}
