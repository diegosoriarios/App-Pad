package com.diego.apppad.pairing

import com.diego.apppad.crypto.AirPadCrypto
import org.json.JSONObject
import java.util.Base64

/**
 * Byte-exact codec, key schedule and traffic cipher for the AirPad v2
 * pairing/transport protocol (PROTOCOL.md v2). Mirrors the Mac's
 * `PairingProtocol.swift`.
 *
 * Pure Kotlin + javax.crypto + org.json: no Android framework classes —
 * fully unit-testable on the JVM.
 */
object PairingProtocol {

    // MARK: Frame / message type constants

    /** Encrypted traffic frame. */
    const val FRAME_ENCRYPTED: Byte = 0x10

    /**
     * Control (handshake) message types. Sent as chunked frames:
     * `[type][ctrl][payloadChunk]`, ctrl bit 7 = last chunk, bits 0-6 = chunk length.
     */
    const val MSG_PAIRING_REQUEST: Byte = 0x21      // Android -> Mac
    const val MSG_PAIRING_RESPONSE: Byte = 0x22     // Mac -> Android
    const val MSG_VERIFY_A: Byte = 0x23             // Android -> Mac
    const val MSG_VERIFY_M: Byte = 0x24             // Mac -> Android
    const val MSG_RECONNECT_INIT: Byte = 0x25       // Mac -> Android
    const val MSG_RECONNECT_RESPONSE: Byte = 0x26   // Android -> Mac
    const val MSG_ERROR: Byte = 0x27                // either direction

    object ErrorCode {
        const val UNKNOWN_DEVICE: Int = 1
        const val VERIFY_FAILED: Int = 2
        const val BUSY: Int = 3
        const val BAD_REQUEST: Int = 4
    }

    // MARK: Layout constants

    const val PUBLIC_KEY_LENGTH = 65           // 0x04 || X || Y (x9.63 uncompressed)
    const val DEVICE_ID_LENGTH = 16
    const val OTP_LENGTH = 16
    const val VERIFY_TAG_LENGTH = 32
    const val PROTOCOL_MINOR: Byte = 0x02

    /** Control chunks must fit the 20-byte default ATT payload even at MTU 23. */
    const val CHUNK_SIZE = 18

    /** One complete control message (reassembled) or single frame on the wire. */
    data class Message(val type: Byte, val payload: ByteArray)

    // MARK: Key schedule

    class SessionSecrets(
        val verifyKeyA: ByteArray,   // HMAC key for Android's tag
        val verifyKeyM: ByteArray,   // HMAC key for Mac's tag
        val session: ByteArray       // master secret for traffic keys
    )

    class TrafficKeys(val a2m: ByteArray, val m2a: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is TrafficKeys &&
                AirPadCrypto.constantTimeEquals(a2m, other.a2m) &&
                AirPadCrypto.constantTimeEquals(m2a, other.m2a)

        override fun hashCode(): Int = a2m.contentHashCode() * 31 + m2a.contentHashCode()
    }

    /** HKDF for the pairing flow: Z1 = ECDH(eph, eph), Z2 = ECDH(lt, lt). */
    fun derivePairingSecrets(z1: ByteArray, z2: ByteArray, transcript: ByteArray): SessionSecrets =
        deriveSecrets(z1 + z2, transcript, "AirPad v2 pairing".toByteArray())

    /**
     * HKDF for the reconnect flow: Z1 = ECDH(eph, eph),
     * Z2 = ECDH(androidLT, macEph), Z3 = ECDH(androidEph, macLT).
     */
    fun deriveReconnectSecrets(z1: ByteArray, z2: ByteArray, z3: ByteArray, transcript: ByteArray): SessionSecrets =
        deriveSecrets(z1 + z2 + z3, transcript, "AirPad v2 reconnect".toByteArray())

    private fun deriveSecrets(ikm: ByteArray, transcript: ByteArray, info: ByteArray): SessionSecrets {
        val okm = AirPadCrypto.hkdfSha256(ikm, transcript, info, 96)
        return SessionSecrets(
            verifyKeyA = okm.copyOfRange(0, 32),
            verifyKeyM = okm.copyOfRange(32, 64),
            session = okm.copyOfRange(64, 96)
        )
    }

    /** Traffic keys are derived once per session from the session secret. */
    fun deriveTrafficKeys(session: ByteArray): TrafficKeys {
        val salt = "AirPad-traffic".toByteArray()
        return TrafficKeys(
            a2m = AirPadCrypto.hkdfSha256(session, salt, byteArrayOf(0x01), 32),
            m2a = AirPadCrypto.hkdfSha256(session, salt, byteArrayOf(0x02), 32)
        )
    }

    /** Mixes an OTP into a session secret: okm = HKDF(session || OTP). */
    fun bindOTP(otp: ByteArray, base: SessionSecrets, transcript: ByteArray): SessionSecrets {
        val bound = AirPadCrypto.hkdfSha256(base.session + otp, transcript, "AirPad v2 otp-bind".toByteArray(), 96)
        return SessionSecrets(
            verifyKeyA = bound.copyOfRange(0, 32),
            verifyKeyM = bound.copyOfRange(32, 64),
            session = bound.copyOfRange(64, 96)
        )
    }

    fun verifyTagA(key: ByteArray, transcript: ByteArray): ByteArray =
        AirPadCrypto.hmacSha256(key, byteArrayOf(0x41) + transcript)

    fun verifyTagM(key: ByteArray, transcript: ByteArray): ByteArray =
        AirPadCrypto.hmacSha256(key, byteArrayOf(0x4D) + transcript)

    /** The 6-digit PIN fallback derives the same 16-byte OTP both sides. */
    fun otpFromPin(pin: String): ByteArray =
        AirPadCrypto.sha256("AirPadPIN".toByteArray() + pin.toByteArray()).copyOfRange(0, OTP_LENGTH)

    // MARK: Chunked control-frame transport

    /** Splits `payload` into chunked frames: `[type][ctrl][chunk]`. */
    fun chunkMessage(type: Byte, payload: ByteArray, chunkSize: Int = CHUNK_SIZE): List<ByteArray> {
        val frames = mutableListOf<ByteArray>()
        val effective = if (payload.isEmpty()) {
            listOf(ByteArray(0))
        } else {
            (payload.indices step chunkSize).map { payload.copyOfRange(it, minOf(it + chunkSize, payload.size)) }
        }
        for ((index, chunk) in effective.withIndex()) {
            val isLast = index == effective.size - 1
            val frame = ByteArray(2 + chunk.size)
            frame[0] = type
            frame[1] = ((if (isLast) 0x80 else 0x00) or chunk.size).toByte()
            chunk.copyInto(frame, 2)
            frames.add(frame)
        }
        return frames
    }

    /** Reassembles chunked control frames; returns the message on the last chunk. */
    class Defragmenter {
        private val buffers = HashMap<Byte, ByteArray>()

        fun feed(frame: ByteArray): Message? {
            if (frame.size < 2) return null
            val type = frame[0]
            val ctrl = frame[1].toInt() and 0xFF
            val isLast = ctrl and 0x80 != 0
            val length = ctrl and 0x7F
            if (frame.size != length + 2) return null
            buffers[type] = (buffers[type] ?: ByteArray(0)) + frame.copyOfRange(2, frame.size)
            if (!isLast) return null
            val payload = buffers.remove(type) ?: ByteArray(0)
            return Message(type, payload)
        }

        fun reset() = buffers.clear()
    }

    // MARK: Message payloads

    /** 0x21 Android -> Mac: `[minor][deviceId 16][ephPub 65][ltPub 65][nameLen][name]` */
    fun buildPairingRequest(deviceId: ByteArray, ephemeralPub: ByteArray, identityPub: ByteArray, name: String): ByteArray =
        byteArrayOf(PROTOCOL_MINOR) + deviceId + ephemeralPub + identityPub + encodeString(name)

    fun parsePairingRequest(payload: ByteArray): PairingRequest? {
        if (payload.size < 1 + DEVICE_ID_LENGTH + PUBLIC_KEY_LENGTH * 2 + 1) return null
        if (payload[0] != PROTOCOL_MINOR) return null
        var offset = 1
        val deviceId = payload.copyOfRange(offset, offset + DEVICE_ID_LENGTH); offset += DEVICE_ID_LENGTH
        val eph = payload.copyOfRange(offset, offset + PUBLIC_KEY_LENGTH); offset += PUBLIC_KEY_LENGTH
        val lt = payload.copyOfRange(offset, offset + PUBLIC_KEY_LENGTH); offset += PUBLIC_KEY_LENGTH
        val name = decodeString(payload, offset) ?: return null
        return PairingRequest(deviceId, eph, lt, name)
    }

    class PairingRequest(
        val deviceId: ByteArray,
        val ephemeralPub: ByteArray,
        val identityPub: ByteArray,
        val name: String
    )

    /**
     * 0x22 Mac -> Android:
     * `[minor][macEphPub 65][macLtPub 65][macId 16][nameLen][name]`
     *
     * The long-term key lets a PIN-only phone (never scanned the QR)
     * authenticate the Mac and derive ECDH-Z2.
     */
    fun buildPairingResponse(macEphemeralPub: ByteArray, macIdentityPub: ByteArray, macId: ByteArray, name: String): ByteArray =
        byteArrayOf(PROTOCOL_MINOR) + macEphemeralPub + macIdentityPub + macId + encodeString(name)

    fun parsePairingResponse(payload: ByteArray): PairingResponse? {
        if (payload.size < 1 + PUBLIC_KEY_LENGTH * 2 + DEVICE_ID_LENGTH + 1) return null
        if (payload[0] != PROTOCOL_MINOR) return null
        var offset = 1
        val eph = payload.copyOfRange(offset, offset + PUBLIC_KEY_LENGTH); offset += PUBLIC_KEY_LENGTH
        val lt = payload.copyOfRange(offset, offset + PUBLIC_KEY_LENGTH); offset += PUBLIC_KEY_LENGTH
        val macId = payload.copyOfRange(offset, offset + DEVICE_ID_LENGTH); offset += DEVICE_ID_LENGTH
        val name = decodeString(payload, offset) ?: return null
        return PairingResponse(eph, lt, macId, name)
    }

    class PairingResponse(
        val macEphemeralPub: ByteArray,
        val macIdentityPub: ByteArray,
        val macId: ByteArray,
        val name: String
    )

    /** 0x25 Mac -> Android: `[minor][macId 16][macEphPub 65]` */
    fun buildReconnectInit(macId: ByteArray, macEphemeralPub: ByteArray): ByteArray =
        byteArrayOf(PROTOCOL_MINOR) + macId + macEphemeralPub

    fun parseReconnectInit(payload: ByteArray): ReconnectInit? {
        if (payload.size != 1 + DEVICE_ID_LENGTH + PUBLIC_KEY_LENGTH) return null
        if (payload[0] != PROTOCOL_MINOR) return null
        val macId = payload.copyOfRange(1, 1 + DEVICE_ID_LENGTH)
        val eph = payload.copyOfRange(1 + DEVICE_ID_LENGTH, payload.size)
        return ReconnectInit(macId, eph)
    }

    class ReconnectInit(val macId: ByteArray, val macEphemeralPub: ByteArray)

    /** 0x26 Android -> Mac: `[minor][deviceId 16][ephPub 65]` */
    fun buildReconnectResponse(deviceId: ByteArray, ephemeralPub: ByteArray): ByteArray =
        byteArrayOf(PROTOCOL_MINOR) + deviceId + ephemeralPub

    fun parseReconnectResponse(payload: ByteArray): ReconnectResponse? {
        if (payload.size != 1 + DEVICE_ID_LENGTH + PUBLIC_KEY_LENGTH) return null
        if (payload[0] != PROTOCOL_MINOR) return null
        val deviceId = payload.copyOfRange(1, 1 + DEVICE_ID_LENGTH)
        val eph = payload.copyOfRange(1 + DEVICE_ID_LENGTH, payload.size)
        return ReconnectResponse(deviceId, eph)
    }

    class ReconnectResponse(val deviceId: ByteArray, val ephemeralPub: ByteArray)

    /** 0x27 error payload: `[minor][errorCode]`. */
    fun buildError(code: Int): ByteArray = byteArrayOf(PROTOCOL_MINOR, code.toByte())

    fun parseError(payload: ByteArray): Int? =
        if (payload.size == 2) payload[1].toInt() and 0xFF else null

    // MARK: Encrypted traffic frames

    /**
     * Frame: `[0x10][ctr u32 LE][ciphertext(15) || tag(16)]` = 36 bytes.
     * Nonce: 4-byte direction prefix + 4 zero bytes + counter as u32 big-endian.
     * AAD: the frame's first 5 bytes.
     */
    class TrafficCipher(
        private val key: ByteArray,
        private val prefix: ByteArray
    ) {
        private var counter = 0u
        private var expectedInboundCounter = 0u

        companion object {
            val directionPrefixA2M = "A2M".toByteArray() + byteArrayOf(0x00)
            val directionPrefixM2A = "M2A".toByteArray() + byteArrayOf(0x00)
            const val FRAME_LENGTH = 5 + 15 + 16
            const val V1_PACKET_LENGTH = 15

            fun sender(keys: TrafficKeys, fromAndroid: Boolean): TrafficCipher =
                TrafficCipher(
                    key = if (fromAndroid) keys.a2m else keys.m2a,
                    prefix = if (fromAndroid) directionPrefixA2M else directionPrefixM2A
                )

            fun nonce(prefix: ByteArray, counter: UInt): ByteArray =
                prefix + ByteArray(4) + byteArrayOf(
                    ((counter.toLong() shr 24) and 0xFF).toByte(),
                    ((counter.toLong() shr 16) and 0xFF).toByte(),
                    ((counter.toLong() shr 8) and 0xFF).toByte(),
                    (counter.toLong() and 0xFF).toByte()
                )
        }

        /** Encrypts one 15-byte protocol-v1 packet. */
        fun encrypt(v1Packet: ByteArray): ByteArray {
            require(v1Packet.size == V1_PACKET_LENGTH) { "v1 packet must be 15 bytes" }
            val ctr = counter
            counter = counter + 1u
            val frame = byteArrayOf(FRAME_ENCRYPTED) + u32LittleEndian(ctr)
            val nonce = nonceFor(ctr)
            val body = AirPadCrypto.aesGcmSeal(key, nonce, v1Packet, frame)
            return frame + body
        }

        /** Decrypts an inbound frame; rejects replays (ctr must not regress). */
        fun decrypt(frame: ByteArray): ByteArray? {
            if (frame.size != FRAME_LENGTH || frame[0] != FRAME_ENCRYPTED) return null
            val ctr = readU32LittleEndian(frame, 1)
            if (ctr < expectedInboundCounter) return null
            expectedInboundCounter = ctr + 1u
            val aad = frame.copyOfRange(0, 5)
            val nonce = nonceFor(ctr)
            val plain = try {
                AirPadCrypto.aesGcmOpen(key, nonce, frame.copyOfRange(5, frame.size), aad)
            } catch (e: Exception) {
                return null
            }
            return if (plain.size == V1_PACKET_LENGTH) plain else null
        }

        private fun nonceFor(ctr: UInt): ByteArray = nonce(prefix, ctr)

        private fun u32LittleEndian(value: UInt): ByteArray = byteArrayOf(
            (value.toLong() and 0xFF).toByte(),
            ((value.toLong() shr 8) and 0xFF).toByte(),
            ((value.toLong() shr 16) and 0xFF).toByte(),
            ((value.toLong() shr 24) and 0xFF).toByte()
        )

        private fun readU32LittleEndian(data: ByteArray, offset: Int): UInt =
            ((data[offset].toLong() and 0xFF) or
                ((data[offset + 1].toLong() and 0xFF) shl 8) or
                ((data[offset + 2].toLong() and 0xFF) shl 16) or
                ((data[offset + 3].toLong() and 0xFF) shl 24)).toUInt()
    }

    // MARK: Pairing offer (QR payload / PIN)

    /**
     * What the Mac displays as a QR code; this app scans it. The QR OTP and
     * the PIN fallback both bind the same session; either verifies.
     */
    data class PairingOffer(
        val macId: ByteArray,
        val macName: String,
        val identityPub: ByteArray,
        val qrOtp: ByteArray
    ) {
        /** The OTP embedded in the QR payload. */
        val otp: ByteArray get() = qrOtp

        override fun equals(other: Any?): Boolean =
            other is PairingOffer &&
                macId.contentEquals(other.macId) &&
                macName == other.macName &&
                identityPub.contentEquals(other.identityPub) &&
                qrOtp.contentEquals(other.qrOtp)

        override fun hashCode(): Int =
            macId.contentHashCode() * 31 + macName.hashCode() + identityPub.contentHashCode() * 7 + qrOtp.contentHashCode()
    }

    fun randomOTP(): ByteArray = AirPadCrypto.randomBytes(OTP_LENGTH)

    fun randomPIN(): String = "%06d".format(AirPadCrypto.randomBytes(3).let { b ->
        ((b[0].toInt() and 0xFF) shl 16) or ((b[1].toInt() and 0xFF) shl 8) or (b[2].toInt() and 0xFF)
    } % 1_000_000)

    /**
     * QR payload: JSON, identical to the Mac's `encodeOfferQR`.
     * `{"v":"2","t":"airpad","name":...,"macId":b64,"key":b64,"otp":b64}`
     */
    fun encodeOfferQR(offer: PairingOffer): String {
        val json = JSONObject()
        json.put("v", "2")
        json.put("t", "airpad")
        json.put("name", offer.macName)
        json.put("macId", Base64.getEncoder().encodeToString(offer.macId))
        json.put("key", Base64.getEncoder().encodeToString(offer.identityPub))
        json.put("otp", Base64.getEncoder().encodeToString(offer.qrOtp))
        return json.toString()
    }

    fun decodeOfferQR(text: String): PairingOffer? = try {
        val json = JSONObject(text)
        if (json.optString("t") != "airpad") null else {
            val macId = Base64.getDecoder().decode(json.getString("macId"))
            val key = Base64.getDecoder().decode(json.getString("key"))
            val otp = Base64.getDecoder().decode(json.getString("otp"))
            if (macId.size != DEVICE_ID_LENGTH || key.size != PUBLIC_KEY_LENGTH || otp.size != OTP_LENGTH) {
                null
            } else {
                PairingOffer(macId, json.getString("name"), key, otp)
            }
        }
    } catch (e: Exception) {
        null
    }

    // MARK: Private helpers

    private fun encodeString(value: String): ByteArray {
        val utf8 = value.toByteArray(Charsets.UTF_8).copyOfRange(0, minOf(255, value.toByteArray(Charsets.UTF_8).size))
        return byteArrayOf(utf8.size.toByte()) + utf8
    }

    private fun decodeString(payload: ByteArray, offset: Int): String? {
        if (offset >= payload.size) return null
        val length = payload[offset].toInt() and 0xFF
        val end = offset + 1 + length
        if (end > payload.size) return null
        return String(payload, offset + 1, length, Charsets.UTF_8)
    }
}
