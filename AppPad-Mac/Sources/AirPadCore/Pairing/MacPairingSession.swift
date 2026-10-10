import Foundation
import CryptoKit

/// Host (Mac) side of the AirPad v2 pairing/reconnect handshake.
///
/// Pure state machine: feed reassembled control messages in, get frames and
/// events out. The BLE layer only transports bytes. Handles both flows:
///  - pairing:    waits for PAIRING_REQUEST, responds, verifies, stores
///  - reconnect:  sends RECONNECT_INIT, verifies the phone's long-term key
public final class MacPairingSession {
    public enum Mode {
        case pairing(otpCandidates: [Data])  // QR OTP and/or PIN-derived OTP
        case reconnect
    }

    public enum Event: Equatable {
        case devicePaired(TrustedDevice)
        case ready(PairingProtocol.TrafficKeys)
        case failed(String)
        case unknownDevice               // phone is not trusted -> show pairing QR
    }

    public struct HandleResult {
        public let frames: [(type: UInt8, payload: Data)]
        public let events: [Event]
        public static func empty() -> HandleResult { HandleResult(frames: [], events: []) }
    }

    public private(set) var isReady = false

    private let mode: Mode
    private let identity: MacIdentity
    private let lookupDevice: (Data) -> TrustedDevice?

    private let ephemeral = P256.KeyAgreement.PrivateKey()
    private var offer: PairingProtocol.PairingOffer?

    // Pairing state
    private var pendingPhonePublicKey: P256.KeyAgreement.PublicKey?
    private var pendingPhoneLTKey: P256.KeyAgreement.PublicKey?
    private var pendingDeviceId: Data?
    private var pendingDeviceName: String?
    private var transcript = Data()
    private var secretsCandidates: [PairingProtocol.SessionSecrets] = []

    public init(mode: Mode, identity: MacIdentity, lookupDevice: @escaping (Data) -> TrustedDevice?) {
        self.mode = mode
        self.identity = identity
        self.lookupDevice = lookupDevice
        if case .pairing(let candidates) = mode {
            offer = PairingProtocol.PairingOffer(
                macId: identity.macId,
                macName: identity.macName,
                identityPub: identity.publicKeyData,
                qrOtp: candidates.first ?? PairingProtocol.randomOTP(),
                pin: "000000"
            )
        }
    }

    /// Reconnect mode starts by sending RECONNECT_INIT. Pairing mode waits
    /// for the phone (it initiates after scanning the QR / entering the PIN).
    public func start() -> [(type: UInt8, payload: Data)] {
        switch mode {
        case .reconnect:
            let payload = PairingProtocol.buildReconnectInit(
                macId: identity.macId,
                macEphemeralPub: ephemeral.publicKey.x963Representation
            )
            return [(PairingProtocol.msgReconnectInit, payload)]
        case .pairing:
            return []
        }
    }

    /// Feed one reassembled control message.
    public func handle(type: UInt8, payload: Data) -> HandleResult {
        switch type {
        case PairingProtocol.msgPairingRequest:
            return handlePairingRequest(payload)
        case PairingProtocol.msgReconnectResponse:
            return handleReconnectResponse(payload)
        case PairingProtocol.msgVerifyA:
            return handleVerifyA(payload)
        case PairingProtocol.msgError:
            return HandleResult(frames: [], events: [.failed("Phone reported error \(payload.count > 1 ? String(payload[1]) : "?")")])
        default:
            return errorResult(.badRequest)
        }
    }

    // MARK: - Pairing flow

    private func handlePairingRequest(_ payload: Data) -> HandleResult {
        guard !isReady else { return errorResult(.busy) }
        guard case .pairing(let otpCandidates) = mode,
              let request = PairingProtocol.parsePairingRequest(payload),
              let phoneEph = try? P256.KeyAgreement.PublicKey(x963Representation: request.ephemeralPub),
              let phoneLT = try? P256.KeyAgreement.PublicKey(x963Representation: request.identityPub)
        else { return errorResult(.badRequest) }

        pendingPhonePublicKey = phoneEph
        pendingPhoneLTKey = phoneLT
        pendingDeviceId = request.deviceId
        pendingDeviceName = request.name

        let responsePayload = PairingProtocol.buildPairingResponse(
            macEphemeralPub: ephemeral.publicKey.x963Representation,
            macIdentityPub: identity.publicKeyData,
            macId: identity.macId,
            name: identity.macName
        )
        transcript = AirPadCrypto.sha256(payload + responsePayload)

        guard let z1 = try? AirPadCrypto.ecdhP256(privateKey: ephemeral, publicKey: phoneEph),
              let z2 = try? AirPadCrypto.ecdhP256(privateKey: identity.privateKey, publicKey: phoneLT)
        else { return errorResult(.badRequest) }

        let base = PairingProtocol.derivePairingSecrets(z1: z1, z2: z2, transcript: transcript)
        // The OTP never travels over BLE: it only feeds the KDF. Derive one
        // candidate per acceptable OTP (QR / PIN); exactly one must match.
        secretsCandidates = otpCandidates.map { bindOTP(otp: $0, base: base) }

        return HandleResult(frames: [(PairingProtocol.msgPairingResponse, responsePayload)], events: [])
    }

    private func handleVerifyA(_ payload: Data) -> HandleResult {
        guard !secretsCandidates.isEmpty else { return errorResult(.badRequest) }
        guard payload.count == PairingProtocol.verifyTagLength else { return errorResult(.verifyFailed) }

        var matched: PairingProtocol.SessionSecrets?
        for candidate in secretsCandidates {
            let expected = PairingProtocol.verifyTagA(key: candidate.verifyKeyA, transcript: transcript)
            if AirPadCrypto.constantTimeEquals(expected, payload) {
                matched = candidate
            }
        }
        guard let secrets = matched else {
            return HandleResult(
                frames: [(PairingProtocol.msgError, Data([PairingProtocol.protocolMinor, PairingProtocol.ErrorCode.verifyFailed.rawValue]))],
                events: [.failed("Verification failed (wrong QR/PIN?)")]
            )
        }

        // Phone verified -> confirm with our own tag; session is live.
        let tagM = PairingProtocol.verifyTagM(key: secrets.verifyKeyM, transcript: transcript)
        isReady = true
        let keys = PairingProtocol.deriveTrafficKeys(session: secrets.session)

        switch mode {
        case .pairing:
            guard let deviceId = pendingDeviceId,
                  let ltKey = pendingPhoneLTKey, let name = pendingDeviceName
            else { return errorResult(.badRequest) }
            let device = TrustedDevice(deviceId: deviceId, name: name, publicKey: ltKey.x963Representation)
            return HandleResult(
                frames: [(PairingProtocol.msgVerifyM, tagM)],
                events: [.devicePaired(device), .ready(keys)]
            )
        case .reconnect:
            // Device is already trusted; no re-registration.
            return HandleResult(frames: [(PairingProtocol.msgVerifyM, tagM)], events: [.ready(keys)])
        }
    }

    // MARK: - Reconnect flow

    private func handleReconnectResponse(_ payload: Data) -> HandleResult {
        guard !isReady else { return errorResult(.busy) }
        guard let response = PairingProtocol.parseReconnectResponse(payload),
              let phoneEph = try? P256.KeyAgreement.PublicKey(x963Representation: response.ephemeralPub),
              let trusted = lookupDevice(response.deviceId),
              let phoneLT = try? P256.KeyAgreement.PublicKey(x963Representation: trusted.publicKey)
        else { return unknownDeviceResult() }

        pendingDeviceId = response.deviceId
        transcript = AirPadCrypto.sha256(
            PairingProtocol.buildReconnectInit(macId: identity.macId, macEphemeralPub: ephemeral.publicKey.x963Representation) + payload
        )

        guard let z1 = try? AirPadCrypto.ecdhP256(privateKey: ephemeral, publicKey: phoneEph),
              let z2 = try? AirPadCrypto.ecdhP256(privateKey: ephemeral, publicKey: phoneLT),
              let z3 = try? AirPadCrypto.ecdhP256(privateKey: identity.privateKey, publicKey: phoneEph)
        else { return errorResult(.badRequest) }

        secretsCandidates = [PairingProtocol.deriveReconnectSecrets(z1: z1, z2: z2, z3: z3, transcript: transcript)]
        return HandleResult(frames: [], events: [])
    }

    // MARK: - Helpers

    /// Mixes an OTP into a base secret: okm = HKDF(base.session || OTP).
    /// A MITM without the OTP derives different traffic keys and both verify
    /// tags fail.
    private func bindOTP(otp: Data, base: PairingProtocol.SessionSecrets) -> PairingProtocol.SessionSecrets {
        let bound = AirPadCrypto.hkdfSha256(
            ikm: base.session + otp,
            salt: transcript,
            info: Data("AirPad v2 otp-bind".utf8),
            length: 96
        )
        return PairingProtocol.SessionSecrets(
            verifyKeyA: bound.subdata(in: 0..<32),
            verifyKeyM: bound.subdata(in: 32..<64),
            session: bound.subdata(in: 64..<96)
        )
    }

    private func errorResult(_ code: PairingProtocol.ErrorCode) -> HandleResult {
        HandleResult(
            frames: [(PairingProtocol.msgError, Data([PairingProtocol.protocolMinor, code.rawValue]))],
            events: [.failed("Pairing error (\(code.rawValue))")]
        )
    }

    private func unknownDeviceResult() -> HandleResult {
        HandleResult(
            frames: [(PairingProtocol.msgError, Data([PairingProtocol.protocolMinor, PairingProtocol.ErrorCode.unknownDevice.rawValue]))],
            events: [.unknownDevice]
        )
    }
}
