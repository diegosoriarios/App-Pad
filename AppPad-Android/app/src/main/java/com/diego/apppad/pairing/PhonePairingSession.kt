package com.diego.apppad.pairing

import com.diego.apppad.crypto.AirPadCrypto

/**
 * Phone (Android) side of the AirPad v2 pairing/reconnect handshake.
 *
 * Pure state machine: feed reassembled control messages in, get frames and
 * events out. The BLE layer only transports bytes. Flow roles:
 *  - reconnect: the Mac initiates (RECONNECT_INIT on connect)
 *  - pairing:   the phone initiates (after scanning the QR / entering the PIN)
 */
class PhonePairingSession(
    private val identity: PhoneIdentity,
    private val lookupMac: (ByteArray) -> TrustedMac?
) {
    sealed class Event {
        data class MacPaired(val mac: TrustedMac) : Event()
        data class Ready(val keys: PairingProtocol.TrafficKeys) : Event()
        data class Failed(val reason: String) : Event()
        /** The Mac reported an error; `code` is a PairingProtocol.ErrorCode. */
        data class MacError(val code: Int) : Event()
    }

    class Result(
        val messages: List<PairingProtocol.Message>,
        val events: List<Event>
    ) {
        companion object {
            val EMPTY = Result(emptyList(), emptyList())
        }
    }

    private enum class Mode {
        Reconnect,
        Pairing           // OTP bound at startPairing()
    }

    private var mode: Mode = Mode.Reconnect
    private var otp: ByteArray? = null
    private var ephemeral: AirPadCrypto.EcKeyPair? = null

    private var pairingRequestPayload: ByteArray? = null
    private var transcript: ByteArray? = null
    private var secrets: PairingProtocol.SessionSecrets? = null
    private var pendingMac: TrustedMac? = null

    var isReady: Boolean = false
        private set

    private var outboundCipher: PairingProtocol.TrafficCipher? = null

    // MARK: - Phone-initiated pairing (QR / PIN)

    /**
     * Switches to pairing mode with fresh ephemerals and returns the
     * PAIRING_REQUEST message (0x21) to send. `otp` comes from the scanned
     * QR or the 6-digit PIN; the Mac accepts either.
     */
    fun startPairing(otp: ByteArray): List<PairingProtocol.Message> {
        resetFlow(Mode.Pairing)
        this.otp = otp
        val payload = PairingProtocol.buildPairingRequest(
            deviceId = identity.deviceId,
            ephemeralPub = AirPadCrypto.publicKeyToX963(ephemeral!!.publicKey),
            identityPub = identity.publicKeyX963,
            name = identity.name
        )
        pairingRequestPayload = payload
        return listOf(PairingProtocol.Message(PairingProtocol.MSG_PAIRING_REQUEST, payload))
    }

    // MARK: - Message handling

    fun onMessage(type: Byte, payload: ByteArray): Result {
        if (isReady) return Result.EMPTY
        return when (type) {
            PairingProtocol.MSG_PAIRING_RESPONSE -> handlePairingResponse(payload)
            PairingProtocol.MSG_RECONNECT_INIT -> handleReconnectInit(payload)
            PairingProtocol.MSG_VERIFY_M -> handleVerifyM(payload)
            PairingProtocol.MSG_ERROR -> handleMacError(payload)
            else -> Result.EMPTY
        }
    }

    private fun handlePairingResponse(payload: ByteArray): Result {
        val otp = this.otp ?: return Result.EMPTY
        val requestPayload = pairingRequestPayload ?: return Result.EMPTY
        val eph = ephemeral ?: return Result.EMPTY

        val response = PairingProtocol.parsePairingResponse(payload)
            ?: return failed("Malformed pairing response")
        val macEph = parseKey(response.macEphemeralPub) ?: return failed("Malformed Mac ephemeral key")
        val macLt = parseKey(response.macIdentityPub) ?: return failed("Malformed Mac identity key")

        pendingMac = TrustedMac(
            macId = response.macId,
            name = response.name,
            publicKeyX963 = response.macIdentityPub,
            addedAtMillis = System.currentTimeMillis()
        )

        transcript = AirPadCrypto.sha256(requestPayload + payload)

        val z1 = runCatching { AirPadCrypto.ecdhP256(eph.privateKey, macEph) }.getOrNull()
            ?: return failed("ECDH failed")
        val z2 = runCatching { AirPadCrypto.ecdhP256(identity.privateKey, macLt) }.getOrNull()
            ?: return failed("ECDH failed")

        val t = transcript!!
        val bound = PairingProtocol.bindOTP(otp, PairingProtocol.derivePairingSecrets(z1, z2, t), t)
        secrets = bound

        val tag = PairingProtocol.verifyTagA(bound.verifyKeyA, t)
        return Result(
            messages = listOf(PairingProtocol.Message(PairingProtocol.MSG_VERIFY_A, tag)),
            events = emptyList()
        )
    }

    private fun handleReconnectInit(payload: ByteArray): Result {
        val init = PairingProtocol.parseReconnectInit(payload) ?: return Result.EMPTY
        resetFlow(Mode.Reconnect)
        val eph = ephemeral!!

        // A phone that was never paired with this Mac still answers (that is
        // how the Mac learns the device is unknown) but cannot derive Z3,
        // which needs the Mac's long-term public key.
        val known = lookupMac(init.macId)
        val responsePayload = PairingProtocol.buildReconnectResponse(
            identity.deviceId,
            AirPadCrypto.publicKeyToX963(eph.publicKey)
        )
        val t = AirPadCrypto.sha256(payload + responsePayload)
        transcript = t

        val macEph = parseKey(init.macEphemeralPub) ?: return Result.EMPTY
        val z1 = runCatching { AirPadCrypto.ecdhP256(eph.privateKey, macEph) }.getOrDefault(AirPadCrypto.randomBytes(32))
        val z2 = runCatching { AirPadCrypto.ecdhP256(identity.privateKey, macEph) }.getOrDefault(AirPadCrypto.randomBytes(32))
        val z3 = if (known != null) {
            runCatching {
                AirPadCrypto.ecdhP256(eph.privateKey, parseKey(known.publicKeyX963)!!)
            }.getOrDefault(AirPadCrypto.randomBytes(32))
        } else {
            AirPadCrypto.randomBytes(32)
        }

        secrets = PairingProtocol.deriveReconnectSecrets(z1, z2, z3, t)
        val tag = PairingProtocol.verifyTagA(secrets!!.verifyKeyA, t)
        return Result(
            messages = listOf(
                PairingProtocol.Message(PairingProtocol.MSG_RECONNECT_RESPONSE, responsePayload),
                PairingProtocol.Message(PairingProtocol.MSG_VERIFY_A, tag)
            ),
            events = emptyList()
        )
    }

    private fun handleVerifyM(payload: ByteArray): Result {
        val t = transcript ?: return Result.EMPTY
        val s = secrets ?: return Result.EMPTY
        val expected = PairingProtocol.verifyTagM(s.verifyKeyM, t)
        if (!AirPadCrypto.constantTimeEquals(expected, payload)) {
            return failed("Verification failed")
        }

        isReady = true
        val keys = PairingProtocol.deriveTrafficKeys(s.session)
        outboundCipher = PairingProtocol.TrafficCipher.sender(keys, fromAndroid = true)

        val events = mutableListOf<Event>(Event.Ready(keys))
        val mac = pendingMac
        if (mode == Mode.Pairing && mac != null) {
            events.add(0, Event.MacPaired(mac))
        }
        return Result(messages = emptyList(), events = events)
    }

    private fun handleMacError(payload: ByteArray): Result {
        val code = PairingProtocol.parseError(payload) ?: return Result.EMPTY
        return Result(messages = emptyList(), events = listOf(Event.MacError(code)))
    }

    // MARK: - Traffic

    /** Encrypts one 15-byte v1 packet; null until the session is ready. */
    fun encryptV1(packet: ByteArray): ByteArray? =
        outboundCipher?.encrypt(packet)

    // MARK: - Internals

    private fun failed(reason: String): Result =
        Result(messages = emptyList(), events = listOf(Event.Failed(reason)))

    private fun parseKey(x963: ByteArray): java.security.PublicKey? =
        runCatching { AirPadCrypto.publicKeyFromX963(x963) }.getOrNull()

    private fun resetFlow(newMode: Mode) {
        mode = newMode
        otp = if (newMode == Mode.Pairing) otp else null
        ephemeral = AirPadCrypto.generateEcKeyPair()
        pairingRequestPayload = null
        transcript = null
        secrets = null
        pendingMac = null
        isReady = false
        outboundCipher = null
    }
}
