package com.diego.apppad.pairing

import com.diego.apppad.crypto.AirPadCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Byte-level protocol tests plus a Kotlin port of the Mac's
 * `MacPairingSession` (the "MacSimulator") to prove both implementations
 * agree on every handshake step and derive identical traffic keys.
 */
class PairingProtocolTest {

    // MARK: - Chunker

    @Test
    fun testChunkerRoundTripAndMtuBounds() {
        val defrag = PairingProtocol.Defragmenter()
        val payload = AirPadCrypto.randomBytes(500)
        val frames = PairingProtocol.chunkMessage(PairingProtocol.MSG_PAIRING_REQUEST, payload)

        // Every frame must fit the 20-byte default ATT payload (MTU 23)
        for (frame in frames) assertTrue(frame.size <= 20)

        var result: PairingProtocol.Message? = null
        for ((index, frame) in frames.withIndex()) {
            result = defrag.feed(frame)
            if (index != frames.size - 1) assertNull(result)
        }
        assertEquals(PairingProtocol.MSG_PAIRING_REQUEST, result!!.type)
        assertTrue(result.payload.contentEquals(payload))
    }

    // MARK: - Traffic cipher

    @Test
    fun testTrafficCipherRoundTripAndReplayReject() {
        val keys = PairingProtocol.deriveTrafficKeys(AirPadCrypto.randomBytes(32))
        val sender = PairingProtocol.TrafficCipher.sender(keys, fromAndroid = true)
        val receiver = PairingProtocol.TrafficCipher.sender(keys, fromAndroid = true)

        val v1 = byteArrayOf(0x01, 0x01, 0x01) + ByteArray(12) { 0xAB.toByte() }
        val frame = sender.encrypt(v1)
        assertEquals(PairingProtocol.TrafficCipher.FRAME_LENGTH, frame.size)
        assertTrue(receiver.decrypt(frame)!!.contentEquals(v1))

        // Replay rejected
        assertNull(receiver.decrypt(frame))

        // Monotonic counters: gaps allowed, regressions not
        val f1 = sender.encrypt(v1)
        val f2 = sender.encrypt(v1)
        assertTrue(receiver.decrypt(f2)!!.contentEquals(v1)) // f1 "lost" -> still fine
        assertNull(receiver.decrypt(f1))                     // old frame -> replay
    }

    // MARK: - QR offer

    @Test
    fun testOfferQRRoundTrip() {
        val offer = PairingProtocol.PairingOffer(
            macId = AirPadCrypto.randomBytes(16),
            macName = "Diego's MacBook Pro",
            identityPub = AirPadCrypto.publicKeyToX963(AirPadCrypto.generateEcKeyPair().publicKey),
            qrOtp = PairingProtocol.randomOTP()
        )
        val decoded = PairingProtocol.decodeOfferQR(PairingProtocol.encodeOfferQR(offer))
        assertNotNull(decoded)
        assertTrue(decoded!!.macId.contentEquals(offer.macId))
        assertEquals(offer.macName, decoded.macName)
        assertTrue(decoded.identityPub.contentEquals(offer.identityPub))
        assertTrue(decoded.qrOtp.contentEquals(offer.qrOtp))
        assertNull(PairingProtocol.decodeOfferQR("not a qr"))
    }

    // MARK: - Handshake interop (MacSimulator ports MacPairingSession.swift)

    private class MacSimulator(
        private val macId: ByteArray,
        private val macName: String,
        private val lookupDevice: (ByteArray) -> TrustedDevice?
    ) {
        class TrustedDevice(val deviceId: ByteArray, val name: String, val publicKeyX963: ByteArray)

        sealed class Event {
            class DevicePaired(val device: TrustedDevice) : Event()
            class Ready(val keys: PairingProtocol.TrafficKeys) : Event()
            class Failed(val reason: String) : Event()
            object UnknownDevice : Event()
        }

        class Result(
            val frames: List<PairingProtocol.Message>,
            val events: List<Event>
        )

        val identity = AirPadCrypto.generateEcKeyPair()
        var otpCandidates: List<ByteArray> = emptyList()

        private var ephemeral = AirPadCrypto.generateEcKeyPair()
        private var transcript = ByteArray(0)
        private var secretsCandidates: List<PairingProtocol.SessionSecrets> = emptyList()
        private var pendingPhoneEph: PublicKey? = null
        private var pendingPhoneLt: PublicKey? = null
        private var pendingDeviceId: ByteArray? = null
        private var pendingDeviceName: String? = null

        val isReady: Boolean get() = ready
        private var ready = false

        fun start(): List<PairingProtocol.Message> = listOf(
            PairingProtocol.Message(
                PairingProtocol.MSG_RECONNECT_INIT,
                PairingProtocol.buildReconnectInit(macId, AirPadCrypto.publicKeyToX963(ephemeral.publicKey))
            )
        )

        fun handle(type: Byte, payload: ByteArray): Result = when (type) {
            PairingProtocol.MSG_PAIRING_REQUEST -> handlePairingRequest(payload)
            PairingProtocol.MSG_RECONNECT_RESPONSE -> handleReconnectResponse(payload)
            PairingProtocol.MSG_VERIFY_A -> handleVerifyA(payload)
            else -> errorResult(PairingProtocol.ErrorCode.BAD_REQUEST)
        }

        private fun handlePairingRequest(payload: ByteArray): Result {
            val request = PairingProtocol.parsePairingRequest(payload)
                ?: return errorResult(PairingProtocol.ErrorCode.BAD_REQUEST)
            pendingPhoneEph = AirPadCrypto.publicKeyFromX963(request.ephemeralPub)
            pendingPhoneLt = AirPadCrypto.publicKeyFromX963(request.identityPub)
            pendingDeviceId = request.deviceId
            pendingDeviceName = request.name

            val responsePayload = PairingProtocol.buildPairingResponse(
                macEphemeralPub = AirPadCrypto.publicKeyToX963(ephemeral.publicKey),
                macIdentityPub = AirPadCrypto.publicKeyToX963(identity.publicKey),
                macId = macId,
                name = macName
            )
            transcript = AirPadCrypto.sha256(payload + responsePayload)

            val z1 = AirPadCrypto.ecdhP256(ephemeral.privateKey, pendingPhoneEph!!)
            val z2 = AirPadCrypto.ecdhP256(identity.privateKey, pendingPhoneLt!!)
            val base = PairingProtocol.derivePairingSecrets(z1, z2, transcript)
            secretsCandidates = otpCandidates.map { PairingProtocol.bindOTP(it, base, transcript) }

            return Result(
                frames = listOf(PairingProtocol.Message(PairingProtocol.MSG_PAIRING_RESPONSE, responsePayload)),
                events = emptyList()
            )
        }

        private fun handleReconnectResponse(payload: ByteArray): Result {
            val response = PairingProtocol.parseReconnectResponse(payload)
                ?: return unknownDeviceResult()
            val trusted = lookupDevice(response.deviceId) ?: return unknownDeviceResult()

            pendingDeviceId = response.deviceId
            pendingPhoneEph = AirPadCrypto.publicKeyFromX963(response.ephemeralPub)
            pendingPhoneLt = AirPadCrypto.publicKeyFromX963(trusted.publicKeyX963)
            transcript = AirPadCrypto.sha256(
                PairingProtocol.buildReconnectInit(macId, AirPadCrypto.publicKeyToX963(ephemeral.publicKey)) + payload
            )

            val z1 = AirPadCrypto.ecdhP256(ephemeral.privateKey, pendingPhoneEph!!)
            val z2 = AirPadCrypto.ecdhP256(ephemeral.privateKey, pendingPhoneLt!!)
            val z3 = AirPadCrypto.ecdhP256(identity.privateKey, pendingPhoneEph!!)
            secretsCandidates = listOf(PairingProtocol.deriveReconnectSecrets(z1, z2, z3, transcript))
            return Result(emptyList(), emptyList())
        }

        private fun handleVerifyA(payload: ByteArray): Result {
            if (secretsCandidates.isEmpty()) return errorResult(PairingProtocol.ErrorCode.BAD_REQUEST)
            if (payload.size != PairingProtocol.VERIFY_TAG_LENGTH) return errorResult(PairingProtocol.ErrorCode.VERIFY_FAILED)

            var matched: PairingProtocol.SessionSecrets? = null
            for (candidate in secretsCandidates) {
                val expected = PairingProtocol.verifyTagA(candidate.verifyKeyA, transcript)
                if (AirPadCrypto.constantTimeEquals(expected, payload)) matched = candidate
            }
            val secrets = matched
                ?: return Result(
                    frames = listOf(PairingProtocol.Message(PairingProtocol.MSG_ERROR, PairingProtocol.buildError(PairingProtocol.ErrorCode.VERIFY_FAILED))),
                    events = listOf(Event.Failed("Verification failed"))
                )

            ready = true
            val keys = PairingProtocol.deriveTrafficKeys(secrets.session)
            val events = mutableListOf<Event>()
            if (otpCandidates.isNotEmpty()) {
                events.add(Event.DevicePaired(TrustedDevice(pendingDeviceId!!, pendingDeviceName!!, pendingPhoneLt!!.let { AirPadCrypto.publicKeyToX963(it) })))
            }
            events.add(Event.Ready(keys))
            return Result(frames = listOf(PairingProtocol.Message(PairingProtocol.MSG_VERIFY_M, PairingProtocol.verifyTagM(secrets.verifyKeyM, transcript))), events = events)
        }

        private fun errorResult(code: Int): Result = Result(
            frames = listOf(PairingProtocol.Message(PairingProtocol.MSG_ERROR, PairingProtocol.buildError(code))),
            events = listOf(Event.Failed("error $code"))
        )

        private fun unknownDeviceResult(): Result = Result(
            frames = listOf(PairingProtocol.Message(PairingProtocol.MSG_ERROR, PairingProtocol.buildError(PairingProtocol.ErrorCode.UNKNOWN_DEVICE))),
            events = listOf(Event.UnknownDevice)
        )
    }

    private fun makePhone(): PhonePairingSession {
        val pair = AirPadCrypto.generateEcKeyPair()
        val identity = PhoneIdentity(
            deviceId = AirPadCrypto.randomBytes(16),
            privateKey = pair.privateKey,
            publicKey = pair.publicKey,
            name = "Pixel Test"
        )
        return PhonePairingSession(identity) { null }
    }

    @Test
    fun testFullPairingFlowWithQROtp() {
        val macSim = MacSimulator(
            macId = AirPadCrypto.randomBytes(16),
            macName = "Test Mac",
            lookupDevice = { null }
        )
        macSim.otpCandidates = listOf(PairingProtocol.randomOTP(), PairingProtocol.otpFromPin("123456"))
        val phone = makePhone()

        // A -> M: request
        val request = phone.startPairing(macSim.otpCandidates.first())
        val r1 = macSim.handle(request[0].type, request[0].payload)
        assertEquals(PairingProtocol.MSG_PAIRING_RESPONSE, r1.frames[0].type)

        // M -> A: response; A computes and sends tag
        val verifyA = phone.onMessage(r1.frames[0].type, r1.frames[0].payload)
        assertEquals(1, verifyA.messages.size)
        assertEquals(PairingProtocol.MSG_VERIFY_A, verifyA.messages[0].type)

        // A -> M: tag; M verifies and confirms
        val r2 = macSim.handle(verifyA.messages[0].type, verifyA.messages[0].payload)
        assertEquals(PairingProtocol.MSG_VERIFY_M, r2.frames[0].type)
        assertTrue(r2.events.any { it is MacSimulator.Event.DevicePaired })

        // M -> A: verify M; pairing complete
        val verifyM = phone.onMessage(r2.frames[0].type, r2.frames[0].payload)
        assertTrue(phone.isReady)
        assertTrue(verifyM.events.any { it is PhonePairingSession.Event.Ready })
        assertTrue(verifyM.events.any { it is PhonePairingSession.Event.MacPaired })
        val readyEvent = verifyM.events.filterIsInstance<PhonePairingSession.Event.Ready>().first()
        val macReady = r2.events.filterIsInstance<MacSimulator.Event.Ready>().first()
        assertEquals(macReady.keys, readyEvent.keys)

        // Traffic round trip across implementations (same JVM crypto)
        val frame = phone.encryptV1(byteArrayOf(0x01, 0x01, 0x01) + ByteArray(12))
        assertNotNull(frame)
        assertEquals(36, frame!!.size)
        val macCipher = PairingProtocol.TrafficCipher.sender(macReady.keys, fromAndroid = true)
        assertTrue(macCipher.decrypt(frame)!!.contentEquals(byteArrayOf(0x01, 0x01, 0x01) + ByteArray(12)))
    }

    @Test
    fun testPairingWithPinFallbackOtp() {
        val macSim = MacSimulator(AirPadCrypto.randomBytes(16), "Test Mac") { null }
        macSim.otpCandidates = listOf(PairingProtocol.randomOTP(), PairingProtocol.otpFromPin("654321"))
        val phone = makePhone()

        // Phone never scanned the QR: it only knows the PIN.
        val request = phone.startPairing(PairingProtocol.otpFromPin("654321"))
        val r1 = macSim.handle(request[0].type, request[0].payload)
        val verifyA = phone.onMessage(r1.frames[0].type, r1.frames[0].payload)
        val r2 = macSim.handle(verifyA.messages[0].type, verifyA.messages[0].payload)
        assertTrue(macSim.isReady)
        assertTrue(r2.events.any { it is MacSimulator.Event.DevicePaired })

        // M -> A: verify M; pairing complete on the phone too
        assertEquals(PairingProtocol.MSG_VERIFY_M, r2.frames[0].type)
        val verifyM = phone.onMessage(r2.frames[0].type, r2.frames[0].payload)
        assertTrue(phone.isReady)
        assertTrue(verifyM.events.any { it is PhonePairingSession.Event.MacPaired })
        val phoneKeys = verifyM.events.filterIsInstance<PhonePairingSession.Event.Ready>().first().keys
        val macKeys = r2.events.filterIsInstance<MacSimulator.Event.Ready>().first().keys
        assertEquals(macKeys, phoneKeys)
    }

    @Test
    fun testPairingWithWrongOtpFails() {
        val macSim = MacSimulator(AirPadCrypto.randomBytes(16), "Test Mac") { null }
        macSim.otpCandidates = listOf(PairingProtocol.randomOTP(), PairingProtocol.otpFromPin("111111"))
        val phone = makePhone()

        val request = phone.startPairing(PairingProtocol.otpFromPin("999999")) // wrong PIN
        val r1 = macSim.handle(request[0].type, request[0].payload)
        val verifyA = phone.onMessage(r1.frames[0].type, r1.frames[0].payload)
        val r2 = macSim.handle(verifyA.messages[0].type, verifyA.messages[0].payload)
        assertFalse(macSim.isReady)
        assertFalse(phone.isReady)
        assertEquals(PairingProtocol.MSG_ERROR, r2.frames[0].type)
        assertTrue(r2.events.any { it is MacSimulator.Event.Failed })

        // The phone learns of the rejection when it processes the error message.
        val phoneError = phone.onMessage(r2.frames[0].type, r2.frames[0].payload)
        assertTrue(phoneError.events.any { it is PhonePairingSession.Event.MacError })
    }

    @Test
    fun testReconnectFlow() {
        val macId = AirPadCrypto.randomBytes(16)
        val phonePair = AirPadCrypto.generateEcKeyPair()
        val phoneIdentity = PhoneIdentity(
            deviceId = AirPadCrypto.randomBytes(16),
            privateKey = phonePair.privateKey,
            publicKey = phonePair.publicKey,
            name = "Pixel Test"
        )
        val trusted = MacSimulator.TrustedDevice(
            phoneIdentity.deviceId, phoneIdentity.name, AirPadCrypto.publicKeyToX963(phonePair.publicKey)
        )
        val macStore = HashMap<List<Byte>, MacSimulator.TrustedDevice>()
        macStore[trusted.deviceId.toList()] = trusted

        val macSim = MacSimulator(macId, "Test Mac") { deviceId -> macStore[deviceId.toList()] }
        val phone = PhonePairingSession(phoneIdentity) { macIdBytes ->
            // The phone trusts this Mac (macId known)
            if (macIdBytes.contentEquals(macId)) TrustedMac(macId, "Test Mac", AirPadCrypto.publicKeyToX963(macSim.identity.publicKey), 0L) else null
        }

        // M -> A: reconnect init; A answers with response + verify tag
        val init = macSim.start()[0]
        val answer = phone.onMessage(init.type, init.payload)
        assertEquals(2, answer.messages.size)
        assertEquals(PairingProtocol.MSG_RECONNECT_RESPONSE, answer.messages[0].type)
        assertEquals(PairingProtocol.MSG_VERIFY_A, answer.messages[1].type)

        // A -> M: response, then tag
        val r1 = macSim.handle(answer.messages[0].type, answer.messages[0].payload)
        assertTrue(r1.frames.isEmpty())
        val r2 = macSim.handle(answer.messages[1].type, answer.messages[1].payload)
        assertEquals(PairingProtocol.MSG_VERIFY_M, r2.frames[0].type)
        assertTrue(macSim.isReady)

        // A verifies the Mac's tag; session live on both ends
        val verifyM = phone.onMessage(r2.frames[0].type, r2.frames[0].payload)
        assertTrue(phone.isReady)
        val phoneKeys = verifyM.events.filterIsInstance<PhonePairingSession.Event.Ready>().first().keys
        val macKeys = r2.events.filterIsInstance<MacSimulator.Event.Ready>().first().keys
        assertEquals(macKeys, phoneKeys)
    }

    @Test
    fun testReconnectWithUnknownPhoneIsRejected() {
        val macSim = MacSimulator(AirPadCrypto.randomBytes(16), "Test Mac") { null }
        val phone = makePhone()

        val init = macSim.start()[0]
        val answer = phone.onMessage(init.type, init.payload)
        val r2 = macSim.handle(answer.messages[0].type, answer.messages[0].payload)
        assertFalse(macSim.isReady)
        assertEquals(PairingProtocol.MSG_ERROR, r2.frames[0].type)
        assertTrue(r2.events.any { it is MacSimulator.Event.UnknownDevice })
    }
}
