import XCTest
import CryptoKit
@testable import AirPadCore

/// Phone-role counterpart used to simulate the full handshake in-process.
/// Mirrors what the Android app implements (PROTOCOL.md v2).
final class PhoneSimulator {
    let deviceId = AirPadCrypto.randomBytes(16)
    let name = "Pixel Test"
    let identity = P256.KeyAgreement.PrivateKey()
    let ephemeral = P256.KeyAgreement.PrivateKey()

    // Learned at pairing
    var macId: Data?
    var macIdentityPub: P256.KeyAgreement.PublicKey?
    var otp: Data?
    var isReady = false
    private(set) var trafficKeys: PairingProtocol.TrafficKeys?
    private var session: Data?
    private var verifyKeyMForCurrentFlow: Data?
    private var currentTranscript: Data?
    private var pairingRequestPayload: Data?
    private var pairingResponsePayload: Data?

    // MARK: Pairing

    func makePairingRequest(offer: PairingProtocol.PairingOffer) -> (type: UInt8, payload: Data) {
        macId = offer.macId
        macIdentityPub = try! P256.KeyAgreement.PublicKey(x963Representation: offer.identityPub)
        otp = offer.otp
        let payload = PairingProtocol.buildPairingRequest(
            deviceId: deviceId,
            ephemeralPub: ephemeral.publicKey.x963Representation,
            identityPub: identity.publicKey.x963Representation,
            name: name
        )
        pairingRequestPayload = payload
        return (PairingProtocol.msgPairingRequest, payload)
    }

    /// Handles the Mac's PAIRING_RESPONSE; returns the VERIFY_A tag message.
    func handlePairingResponse(_ payload: Data) -> (type: UInt8, payload: Data)? {
        guard let response = PairingProtocol.parsePairingResponse(payload),
              let macEph = try? P256.KeyAgreement.PublicKey(x963Representation: response.macEphemeralPub),
              let macLT = try? P256.KeyAgreement.PublicKey(x963Representation: response.macIdentityPub),
              let otp = otp,
              let requestPayload = pairingRequestPayload
        else { return nil }
        macId = response.macId
        pairingResponsePayload = payload

        let transcript = AirPadCrypto.sha256(requestPayload + payload)
        currentTranscript = transcript

        let z1 = try! AirPadCrypto.ecdhP256(privateKey: ephemeral, publicKey: macEph)
        let z2 = try! AirPadCrypto.ecdhP256(privateKey: identity, publicKey: macLT)
        let base = PairingProtocol.derivePairingSecrets(z1: z1, z2: z2, transcript: transcript)
        let bound = bindOTP(otp: otp, base: base, transcript: transcript)
        session = bound.session

        let tag = PairingProtocol.verifyTagA(key: bound.verifyKeyA, transcript: transcript)
        return (PairingProtocol.msgVerifyA, tag)
    }

    func handleVerifyM(_ payload: Data) -> Bool {
        guard let session = session,
              let verifyKeyM = verifyKeyMForCurrentFlow,
              let transcript = currentTranscript else { return false }
        let expected = PairingProtocol.verifyTagM(key: verifyKeyM, transcript: transcript)
        guard AirPadCrypto.constantTimeEquals(expected, payload) else { return false }
        isReady = true
        trafficKeys = PairingProtocol.deriveTrafficKeys(session: session)
        return true
    }

    // MARK: Reconnect

    /// Handles the Mac's RECONNECT_INIT; returns the RECONNECT_RESPONSE and
    /// the VERIFY_A tag messages, in wire order.
    func handleReconnectInit(_ payload: Data) -> [(type: UInt8, payload: Data)] {
        guard let initMsg = PairingProtocol.parseReconnectInit(payload),
              let macEph = try? P256.KeyAgreement.PublicKey(x963Representation: initMsg.macEphemeralPub)
        else { return [] }

        // A phone that was never paired with this Mac still answers (that is
        // how the Mac learns the device is unknown) but cannot derive Z3,
        // which needs the Mac's long-term public key.
        let knowsMac = macIdentityPub != nil && initMsg.macId == macId

        let responsePayload = PairingProtocol.buildReconnectResponse(
            deviceId: deviceId,
            ephemeralPub: ephemeral.publicKey.x963Representation
        )
        let transcript = AirPadCrypto.sha256(payload + responsePayload)
        currentTranscript = transcript

        let z1 = try! AirPadCrypto.ecdhP256(privateKey: ephemeral, publicKey: macEph)
        let z2 = knowsMac
            ? (try! AirPadCrypto.ecdhP256(privateKey: identity, publicKey: macEph))
            : AirPadCrypto.randomBytes(32)
        let z3 = knowsMac
            ? (try! AirPadCrypto.ecdhP256(privateKey: ephemeral, publicKey: macIdentityPub!))
            : AirPadCrypto.randomBytes(32)
        let secrets = PairingProtocol.deriveReconnectSecrets(z1: z1, z2: z2, z3: z3, transcript: transcript)
        session = secrets.session
        verifyKeyMForCurrentFlow = secrets.verifyKeyM

        let tag = PairingProtocol.verifyTagA(key: secrets.verifyKeyA, transcript: transcript)
        return [
            (PairingProtocol.msgReconnectResponse, responsePayload),
            (PairingProtocol.msgVerifyA, tag)
        ]
    }

    func verifyReconnectTagM(_ tag: Data) -> Bool {
        guard let verifyKeyM = verifyKeyMForCurrentFlow, let transcript = currentTranscript else { return false }
        return AirPadCrypto.constantTimeEquals(tag, PairingProtocol.verifyTagM(key: verifyKeyM, transcript: transcript))
    }

    func finishReconnect() {
        guard let session = session else { return }
        isReady = true
        trafficKeys = PairingProtocol.deriveTrafficKeys(session: session)
    }

    private func bindOTP(otp: Data, base: PairingProtocol.SessionSecrets, transcript: Data) -> PairingProtocol.SessionSecrets {
        let bound = AirPadCrypto.hkdfSha256(
            ikm: base.session + otp,
            salt: transcript,
            info: Data("AirPad v2 otp-bind".utf8),
            length: 96
        )
        verifyKeyMForCurrentFlow = bound.subdata(in: 32..<64)
        return PairingProtocol.SessionSecrets(
            verifyKeyA: bound.subdata(in: 0..<32),
            verifyKeyM: bound.subdata(in: 32..<64),
            session: bound.subdata(in: 64..<96)
        )
    }
}

final class MacPairingSessionTests: XCTestCase {

    private func makeIdentity() -> MacIdentity {
        MacIdentity(
            macName: "Test Mac",
            defaults: UserDefaults(suiteName: "test-\(UUID().uuidString)")!
        )
    }

    private func pairedDeviceOnMac(_ phone: PhoneSimulator, identity: MacIdentity) -> TrustedDevice {
        TrustedDevice(
            deviceId: phone.deviceId,
            name: phone.name,
            publicKey: phone.identity.publicKey.x963Representation
        )
    }

    func testFullPairingFlowWithQROtp() throws {
        let identity = makeIdentity()
        let offer = PairingProtocol.PairingOffer(
            macId: identity.macId,
            macName: identity.macName,
            identityPub: identity.publicKeyData,
            qrOtp: PairingProtocol.randomOTP(),
            pin: "123456"
        )
        let mac = MacPairingSession(mode: .pairing(otpCandidates: offer.otpCandidates), identity: identity) { _ in nil }
        let phone = PhoneSimulator()

        // A -> M: request
        let request = phone.makePairingRequest(offer: offer)
        let r1 = mac.handle(type: request.type, payload: request.payload)
        XCTAssertEqual(r1.frames.first?.type, PairingProtocol.msgPairingResponse)

        // M -> A: response; A computes and sends tag
        let response = try XCTUnwrap(r1.frames.first)
        let verifyA = try XCTUnwrap(phone.handlePairingResponse(response.payload))
        let r2 = mac.handle(type: verifyA.type, payload: verifyA.payload)

        // M -> A: verify M; pairing complete
        let verifyM = try XCTUnwrap(r2.frames.first)
        XCTAssertEqual(verifyM.type, PairingProtocol.msgVerifyM)
        XCTAssertTrue(phone.handleVerifyM(verifyM.payload))
        XCTAssertTrue(phone.isReady)

        XCTAssertTrue(mac.isReady)
        XCTAssertTrue(r2.events.contains { if case .devicePaired = $0 { return true } else { return false } })
        guard case .ready(let macKeys)? = r2.events.last else { return XCTFail("expected ready") }
        XCTAssertEqual(macKeys, phone.trafficKeys)
    }

    func testPairingWithPinFallbackOtp() throws {
        let identity = makeIdentity()
        let offer = PairingProtocol.PairingOffer(
            macId: identity.macId,
            macName: identity.macName,
            identityPub: identity.publicKeyData,
            qrOtp: PairingProtocol.randomOTP(),
            pin: "654321"
        )
        // Phone uses the PIN-derived OTP (no QR scan)
        let mac = MacPairingSession(mode: .pairing(otpCandidates: offer.otpCandidates), identity: identity) { _ in nil }
        let phone = PhoneSimulator()
        var request = phone.makePairingRequest(offer: offer)
        request.payload = request.payload // keep
        phone.overrideOTPForTest(PairingProtocol.otpFromPin("654321"))

        let r1 = mac.handle(type: request.type, payload: request.payload)
        let response = try XCTUnwrap(r1.frames.first)
        let verifyA = try XCTUnwrap(phone.handlePairingResponse(response.payload))
        let r2 = mac.handle(type: verifyA.type, payload: verifyA.payload)
        XCTAssertTrue(mac.isReady)
        XCTAssertTrue(r2.events.contains { if case .devicePaired = $0 { return true } else { return false } })
    }

    func testPairingWithWrongOtpFails() throws {
        let identity = makeIdentity()
        let offer = PairingProtocol.PairingOffer(
            macId: identity.macId,
            macName: identity.macName,
            identityPub: identity.publicKeyData,
            qrOtp: PairingProtocol.randomOTP(),
            pin: "111111"
        )
        let mac = MacPairingSession(mode: .pairing(otpCandidates: offer.otpCandidates), identity: identity) { _ in nil }
        let phone = PhoneSimulator()
        let request = phone.makePairingRequest(offer: offer)
        let r1 = mac.handle(type: request.type, payload: request.payload)
        let response = try XCTUnwrap(r1.frames.first)
        phone.overrideOTPForTest(PairingProtocol.otpFromPin("999999")) // wrong PIN
        let verifyA = try XCTUnwrap(phone.handlePairingResponse(response.payload))
        let r2 = mac.handle(type: verifyA.type, payload: verifyA.payload)
        XCTAssertFalse(mac.isReady)
        XCTAssertEqual(r2.frames.first?.type, PairingProtocol.msgError)
        XCTAssertTrue(r2.events.contains { if case .failed = $0 { return true } else { return false } })
    }

    func testReconnectFlow() throws {
        let identity = makeIdentity()
        let offer = PairingProtocol.PairingOffer(
            macId: identity.macId,
            macName: identity.macName,
            identityPub: identity.publicKeyData,
            qrOtp: PairingProtocol.randomOTP(),
            pin: "000000"
        )

        // --- Learn the Mac's identity (a previous pairing)
        let phone = PhoneSimulator()
        _ = phone.makePairingRequest(offer: offer)
        let stored = pairedDeviceOnMac(phone, identity: identity)

        // --- Reconnect: Mac looks the device up by id
        let mac = MacPairingSession(mode: .reconnect, identity: identity) { [stored] deviceId in
            deviceId == stored.deviceId ? stored : nil
        }

        let start = mac.start()
        XCTAssertEqual(start.first?.type, PairingProtocol.msgReconnectInit)

        let initMsg = try XCTUnwrap(start.first)
        let messages = phone.handleReconnectInit(initMsg.payload)
        XCTAssertEqual(messages.first?.type, PairingProtocol.msgReconnectResponse)

        var r2 = MacPairingSession.HandleResult.empty()
        for message in messages {
            r2 = mac.handle(type: message.type, payload: message.payload)
        }
        let verifyM = try XCTUnwrap(r2.frames.first)
        XCTAssertEqual(verifyM.type, PairingProtocol.msgVerifyM)

        // Phone verifies the Mac's tag, session goes live on both ends
        XCTAssertTrue(phone.verifyReconnectTagM(verifyM.payload))
        phone.finishReconnect()
        XCTAssertTrue(phone.isReady)

        XCTAssertTrue(mac.isReady)
        guard case .ready(let macKeys)? = r2.events.last else { return XCTFail("expected ready") }
        XCTAssertEqual(macKeys, phone.trafficKeys)
    }

    func testReconnectWithUnknownDeviceIsRejected() throws {
        let identity = makeIdentity()
        let mac = MacPairingSession(mode: .reconnect, identity: identity) { _ in nil }
        let start = mac.start()
        let initMsg = try XCTUnwrap(start.first)

        // Unknown phone answers with RECONNECT_RESPONSE; the Mac rejects it
        // by deviceId lookup before any crypto happens.
        let stranger = PhoneSimulator()
        let messages = stranger.handleReconnectInit(initMsg.payload)
        let response = try XCTUnwrap(messages.first)
        XCTAssertEqual(response.type, PairingProtocol.msgReconnectResponse)
        let r2 = mac.handle(type: response.type, payload: response.payload)
        XCTAssertFalse(mac.isReady)
        XCTAssertEqual(r2.frames.first?.type, PairingProtocol.msgError)
        XCTAssertTrue(r2.events.contains { if case .unknownDevice = $0 { return true } else { return false } })
    }

    func testTrafficCipherRoundTripAndReplayReject() throws {
        let keys = PairingProtocol.deriveTrafficKeys(session: AirPadCrypto.randomBytes(32))
        var sender = PairingProtocol.TrafficCipher.sender(for: keys, fromAndroid: true)
        var receiver = PairingProtocol.TrafficCipher.sender(for: keys, fromAndroid: true)

        let v1 = Data([0x01, 0x01, 0x01]) + Data(repeating: 0xAB, count: 12)
        let frame = try sender.encrypt(v1Packet: v1)
        XCTAssertEqual(frame.count, PairingProtocol.TrafficCipher.frameLength)
        XCTAssertEqual(try receiver.decrypt(frame: frame), v1)

        // Replay rejected
        XCTAssertNil(receiver.decrypt(frame: frame))

        // Monotonic counters: gaps allowed, regressions not
        let f1 = try sender.encrypt(v1Packet: v1)
        let f2 = try sender.encrypt(v1Packet: v1)
        XCTAssertEqual(try receiver.decrypt(frame: f2), v1) // f1 "lost" -> still fine
        XCTAssertNil(receiver.decrypt(frame: f1))           // old frame -> replay
    }

    func testChunkerRoundTrip() {
        var defrag = PairingProtocol.Defragmenter()
        let payload = AirPadCrypto.randomBytes(500)
        let frames = PairingProtocol.chunkMessage(type: 0x21, payload: payload)

        var result: (type: UInt8, payload: Data)?
        for frame in frames {
            result = defrag.feed(frame)
            if frames.last != frame { XCTAssertNil(result) }
        }
        XCTAssertEqual(result?.type, 0x21)
        XCTAssertEqual(result?.payload, payload)
    }

    func testOfferQRRoundTrip() {
        let offer = PairingProtocol.PairingOffer(
            macId: AirPadCrypto.randomBytes(16),
            macName: "Diego's MacBook Pro",
            identityPub: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            qrOtp: PairingProtocol.randomOTP(),
            pin: "012345"
        )
        let qr = PairingProtocol.encodeOfferQR(offer)
        let decoded = PairingProtocol.decodeOfferQR(qr)
        XCTAssertEqual(decoded?.macId, offer.macId)
        XCTAssertEqual(decoded?.macName, offer.macName)
        XCTAssertEqual(decoded?.identityPub, offer.identityPub)
        XCTAssertEqual(decoded?.otp, offer.otp)
        XCTAssertNil(PairingProtocol.decodeOfferQR("not a qr"))
    }

    // MARK: helpers
}

extension PhoneSimulator {
    func overrideOTPForTest(_ otp: Data) {
        self.otp = otp
    }
}
