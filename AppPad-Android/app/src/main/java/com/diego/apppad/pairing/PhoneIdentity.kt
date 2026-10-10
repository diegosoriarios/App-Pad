package com.diego.apppad.pairing

import android.content.Context
import android.os.Build
import android.util.Base64
import com.diego.apppad.crypto.AirPadCrypto

/**
 * This phone's long-term AirPad identity: a P-256 key agreement keypair plus
 * a stable random 16-byte deviceId.
 *
 * Storage decision (documented trade-off): the private key is stored as
 * PKCS#8 in app-private SharedPreferences instead of AndroidKeyStore.
 * AndroidKeyStore cannot export ECDH shared secrets (`PURPOSE_AGREE_KEY`
 * needs API 31+), and we must support Android 9 (API 28). The key is
 * therefore protected only by app sandboxing, which matches the threat
 * model: a BLE MITM without the OTP cannot derive the session keys.
 */
class PhoneIdentity(
    val deviceId: ByteArray,
    val privateKey: java.security.PrivateKey,
    val publicKey: java.security.PublicKey,
    val name: String
) {
    val publicKeyX963: ByteArray get() = AirPadCrypto.publicKeyToX963(publicKey)

    companion object {
        private const val PREFS = "airpad.identity"
        private const val KEY_DEVICE_ID = "deviceId"
        private const val KEY_PRIVATE = "privateKeyPkcs8"
        private const val KEY_PUBLIC = "publicKeyX963"

        fun load(context: Context): PhoneIdentity {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val name = Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android Phone"

            val storedPrivate = prefs.getString(KEY_PRIVATE, null)
            val storedPublic = prefs.getString(KEY_PUBLIC, null)
            val storedId = prefs.getString(KEY_DEVICE_ID, null)

            if (storedPrivate != null && storedPublic != null && storedId != null) {
                try {
                    val privateKey = AirPadCrypto.privateKeyFromStored(Base64.decode(storedPrivate, Base64.NO_WRAP))
                    val x963 = Base64.decode(storedPublic, Base64.NO_WRAP)
                    val deviceId = Base64.decode(storedId, Base64.NO_WRAP)
                    if (deviceId.size == PairingProtocol.DEVICE_ID_LENGTH && x963.size == PairingProtocol.PUBLIC_KEY_LENGTH) {
                        return PhoneIdentity(deviceId, privateKey, AirPadCrypto.publicKeyFromX963(x963), name)
                    }
                } catch (e: Exception) {
                    // fall through to regeneration on corrupt storage
                }
            }

            val pair = AirPadCrypto.generateEcKeyPair()
            val deviceId = AirPadCrypto.randomBytes(PairingProtocol.DEVICE_ID_LENGTH)
            prefs.edit()
                .putString(KEY_PRIVATE, Base64.encodeToString(AirPadCrypto.privateKeyToStored(pair.privateKey), Base64.NO_WRAP))
                .putString(KEY_PUBLIC, Base64.encodeToString(AirPadCrypto.publicKeyToX963(pair.publicKey), Base64.NO_WRAP))
                .putString(KEY_DEVICE_ID, Base64.encodeToString(deviceId, Base64.NO_WRAP))
                .apply()
            return PhoneIdentity(deviceId, pair.privateKey, pair.publicKey, name)
        }
    }
}
