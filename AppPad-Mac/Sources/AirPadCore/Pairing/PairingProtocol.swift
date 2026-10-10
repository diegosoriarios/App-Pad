import Foundation
import CryptoKit

/// Byte-exact codec, key schedule and traffic cipher for the AirPad v2
/// pairing/transport protocol (PROTOCOL.md v2).
///
/// Pure Foundation + CryptoKit: no BLE, no UI — fully unit-testable.
public enum PairingProtocol {
    // MARK: Frame / message type constants

    /// Encrypted traffic frame.
    public static let frameEncrypted: UInt8 = 0x10

    /// Control (handshake) message types. Sent as chunked frames:
    /// `[type][ctrl][payloadChunk]`, ctrl bit 7 = last chunk, bits 0-6 = chunk length.
    public static let msgPairingRequest: UInt8 = 0x21      // Android -> Mac
    public static let msgPairingResponse: UInt8 = 0x22     // Mac -> Android
    public static let msgVerifyA: UInt8 = 0x23             // Android -> Mac
    public static let msgVerifyM: UInt8 = 0x24             // Mac -> Android
    public static let msgReconnectInit: UInt8 = 0x25       // Mac -> Android
    public static let msgReconnectResponse: UInt8 = 0x26   // Android -> Mac
    public static let msgError: UInt8 = 0x27               // either direction

    public enum ErrorCode: UInt8 {
        case unknownDevice = 1
        case verifyFailed = 2
        case busy = 3
        case badRequest = 4
    }

    // MARK: Layout constants

    public static let publicKeyLength = 65          // 0x04 || X || Y (x9.63 uncompressed)
    public static let deviceIdLength = 16
    public static let otpLength = 16
    public static let verifyTagLength = 32
    public static let protocolMinor: UInt8 = 0x02

    // MARK: Key schedule

    public struct SessionSecrets: Equatable {
        public let verifyKeyA: Data     // HMAC key for Android's tag
        public let verifyKeyM: Data     // HMAC key for Mac's tag
        public let session: Data        // master secret for traffic keys
    }

    public struct TrafficKeys: Equatable {
        public let a2m: Data            // Android -> Mac AES-256-GCM key
        public let m2a: Data            // Mac -> Android AES-256-GCM key
    }

    /// HKDF for the pairing flow: Z1 = ECDH(eph, eph), Z2 = ECDH(lt, lt).
    public static func derivePairingSecrets(z1: Data, z2: Data, transcript: Data) -> SessionSecrets {
        deriveSecrets(ikm: z1 + z2, transcript: transcript, info: Data("AirPad v2 pairing".utf8))
    }

    /// HKDF for the reconnect flow: Z1 = ECDH(eph, eph),
    /// Z2 = ECDH(androidLT, macEph), Z3 = ECDH(androidEph, macLT).
    public static func deriveReconnectSecrets(z1: Data, z2: Data, z3: Data, transcript: Data) -> SessionSecrets {
        deriveSecrets(ikm: z1 + z2 + z3, transcript: transcript, info: Data("AirPad v2 reconnect".utf8))
    }

    private static func deriveSecrets(ikm: Data, transcript: Data, info: Data) -> SessionSecrets {
        let okm = AirPadCrypto.hkdfSha256(ikm: ikm, salt: transcript, info: info, length: 96)
        return SessionSecrets(
            verifyKeyA: okm.subdata(in: 0..<32),
            verifyKeyM: okm.subdata(in: 32..<64),
            session: okm.subdata(in: 64..<96)
        )
    }

    /// Traffic keys are derived once per session from the session secret.
    public static func deriveTrafficKeys(session: Data) -> TrafficKeys {
        let salt = Data("AirPad-traffic".utf8)
        return TrafficKeys(
            a2m: AirPadCrypto.hkdfSha256(ikm: session, salt: salt, info: Data([0x01]), length: 32),
            m2a: AirPadCrypto.hkdfSha256(ikm: session, salt: salt, info: Data([0x02]), length: 32)
        )
    }

    public static func verifyTagA(key: Data, transcript: Data) -> Data {
        AirPadCrypto.hmacSha256(key: key, message: Data([0x41]) + transcript)
    }

    public static func verifyTagM(key: Data, transcript: Data) -> Data {
        AirPadCrypto.hmacSha256(key: key, message: Data([0x4D]) + transcript)
    }

    /// The 6-digit PIN fallback derives the same 16-byte OTP both sides.
    public static func otpFromPin(_ pin: String) -> Data {
        AirPadCrypto.sha256(Data("AirPadPIN".utf8) + Data(pin.utf8)).prefix(otpLength)
    }

    // MARK: Chunked control-frame transport

    /// Splits `payload` into chunked frames of the given message type.
    /// Frame layout: `[type][ctrl][chunk]`, ctrl = (last ? 0x80 : 0) | chunkLen.
    /// Chunks stay within the 20-byte default ATT payload so handshakes work
    /// even if MTU negotiation fails (18 payload + 2 header).
    public static func chunkMessage(type: UInt8, payload: Data, chunkSize: Int = 18) -> [Data] {
        var frames: [Data] = []
        let chunks = stride(from: 0, to: max(payload.count, 1), by: chunkSize).map {
            payload.subdata(in: $0..<min($0 + chunkSize, payload.count))
        }
        let effective = payload.isEmpty ? [Data()] : chunks
        for (index, chunk) in effective.enumerated() {
            let isLast = index == effective.count - 1
            var frame = Data([type, (isLast ? 0x80 : 0x00) | UInt8(chunk.count)])
            frame.append(chunk)
            frames.append(frame)
        }
        return frames
    }

    /// Reassembles chunked control frames; returns the complete message when
    /// the last chunk of a type arrives.
    public struct Defragmenter {
        private var buffers: [UInt8: Data] = [:]

        public init() {}

        public mutating func feed(_ frame: Data) -> (type: UInt8, payload: Data)? {
            guard frame.count >= 2 else { return nil }
            let type = frame[0]
            let ctrl = frame[1]
            let isLast = ctrl & 0x80 != 0
            let length = Int(ctrl & 0x7F)
            guard frame.count == length + 2 else { return nil }
            buffers[type, default: Data()].append(frame.subdata(in: 2..<frame.count))
            guard isLast else { return nil }
            let payload = buffers.removeValue(forKey: type) ?? Data()
            return (type, payload)
        }

        public mutating func reset() {
            buffers.removeAll()
        }
    }

    // MARK: Message payloads

    /// 0x21 Android -> Mac: `[minor][deviceId 16][ephPub 65][ltPub 65][nameLen][name]`
    public static func buildPairingRequest(deviceId: Data, ephemeralPub: Data, identityPub: Data, name: String) -> Data {
        Data([protocolMinor]) + deviceId + ephemeralPub + identityPub + encodeString(name)
    }

    public static func parsePairingRequest(_ payload: Data) -> (deviceId: Data, ephemeralPub: Data, identityPub: Data, name: String)? {
        guard payload.count >= 1 + deviceIdLength + publicKeyLength * 2 + 1 else { return nil }
        guard payload[0] == protocolMinor else { return nil }
        var offset = 1
        let deviceId = payload.subdata(in: offset..<offset + deviceIdLength); offset += deviceIdLength
        let eph = payload.subdata(in: offset..<offset + publicKeyLength); offset += publicKeyLength
        let lt = payload.subdata(in: offset..<offset + publicKeyLength); offset += publicKeyLength
        guard let name = decodeString(payload, at: offset) else { return nil }
        return (deviceId, eph, lt, name)
    }

    /// 0x22 Mac -> Android:
    /// `[minor][macEphPub 65][macLtPub 65][macId 16][nameLen][name]`
    /// The long-term key lets a PIN-only phone authenticate the Mac and
    /// derive ECDH-Z2 without ever having scanned the QR.
    public static func buildPairingResponse(macEphemeralPub: Data, macIdentityPub: Data, macId: Data, name: String) -> Data {
        Data([protocolMinor]) + macEphemeralPub + macIdentityPub + macId + encodeString(name)
    }

    public static func parsePairingResponse(_ payload: Data) -> (macEphemeralPub: Data, macIdentityPub: Data, macId: Data, name: String)? {
        guard payload.count >= 1 + publicKeyLength * 2 + deviceIdLength + 1 else { return nil }
        guard payload[0] == protocolMinor else { return nil }
        var offset = 1
        let eph = payload.subdata(in: offset..<offset + publicKeyLength); offset += publicKeyLength
        let lt = payload.subdata(in: offset..<offset + publicKeyLength); offset += publicKeyLength
        let macId = payload.subdata(in: offset..<offset + deviceIdLength); offset += deviceIdLength
        guard let name = decodeString(payload, at: offset) else { return nil }
        return (eph, lt, macId, name)
    }

    /// 0x25 Mac -> Android: `[minor][macId 16][macEphPub 65]`
    public static func buildReconnectInit(macId: Data, macEphemeralPub: Data) -> Data {
        Data([protocolMinor]) + macId + macEphemeralPub
    }

    public static func parseReconnectInit(_ payload: Data) -> (macId: Data, macEphemeralPub: Data)? {
        guard payload.count == 1 + deviceIdLength + publicKeyLength, payload[0] == protocolMinor else { return nil }
        let macId = payload.subdata(in: 1..<1 + deviceIdLength)
        let eph = payload.subdata(in: 1 + deviceIdLength..<1 + deviceIdLength + publicKeyLength)
        return (macId, eph)
    }

    /// 0x26 Android -> Mac: `[minor][deviceId 16][ephPub 65]`
    public static func buildReconnectResponse(deviceId: Data, ephemeralPub: Data) -> Data {
        Data([protocolMinor]) + deviceId + ephemeralPub
    }

    public static func parseReconnectResponse(_ payload: Data) -> (deviceId: Data, ephemeralPub: Data)? {
        guard payload.count == 1 + deviceIdLength + publicKeyLength, payload[0] == protocolMinor else { return nil }
        let deviceId = payload.subdata(in: 1..<1 + deviceIdLength)
        let eph = payload.subdata(in: 1 + deviceIdLength..<1 + deviceIdLength + publicKeyLength)
        return (deviceId, eph)
    }

    // MARK: Encrypted traffic frames

    /// Frame: `[0x10][ctr u32 LE][ciphertext(15) || tag(16)]` = 36 bytes.
    /// Nonce: 4-byte direction prefix + 4 zero bytes + counter as u32 big-endian.
    /// AAD: the frame's first 5 bytes.
    public struct TrafficCipher {
        public static let directionPrefixA2M = Data("A2M".utf8) + Data([0x00])
        public static let directionPrefixM2A = Data("M2A".utf8) + Data([0x00])
        public static let frameLength = 5 + 15 + 16
        public static let v1PacketLength = 15

        private let key: Data
        private let prefix: Data
        private var counter: UInt32
        private var expectedInboundCounter: UInt32

        public init(key: Data, prefix: Data) {
            self.key = key
            self.prefix = prefix
            self.counter = 0
            self.expectedInboundCounter = 0
        }

        public static func sender(for keys: TrafficKeys, fromAndroid: Bool) -> TrafficCipher {
            TrafficCipher(key: fromAndroid ? keys.a2m : keys.m2a,
                          prefix: fromAndroid ? directionPrefixA2M : directionPrefixM2A)
        }

        /// Encrypts one 15-byte protocol-v1 packet.
        public mutating func encrypt(v1Packet: Data) throws -> Data {
            guard v1Packet.count == Self.v1PacketLength else { throw AirPadCrypto.CryptoError.invalidCiphertext }
            let ctr = counter
            counter &+= 1
            let frame = Data([PairingProtocol.frameEncrypted]) + Self.littleEndian(ctr)
            let nonce = prefix + Data(repeating: 0, count: 4) + Self.bigEndian(ctr)
            let body = try AirPadCrypto.aesGcmSeal(key: key, nonce: nonce, plaintext: v1Packet, aad: frame)
            return frame + body
        }

        /// Decrypts an inbound frame; rejects replays (ctr must not regress).
        public mutating func decrypt(frame: Data) -> Data? {
            guard frame.count == Self.frameLength, frame[0] == PairingProtocol.frameEncrypted else { return nil }
            let ctr = Self.readLittleEndianU32(frame.subdata(in: 1..<5))
            guard ctr >= expectedInboundCounter else { return nil }
            expectedInboundCounter = ctr &+ 1
            let aad = frame.subdata(in: 0..<5)
            let nonce = prefix + Data(repeating: 0, count: 4) + Self.bigEndian(ctr)
            guard let plain = try? AirPadCrypto.aesGcmOpen(
                key: key, nonce: nonce,
                ciphertextAndTag: frame.subdata(in: 5..<frame.count),
                aad: aad
            ), plain.count == Self.v1PacketLength else { return nil }
            return plain
        }

        public static func nonceForTests(prefix: Data, counter: UInt32) -> Data {
            prefix + Data(repeating: 0, count: 4) + bigEndian(counter)
        }

        private static func bigEndian(_ value: UInt32) -> Data {
            withUnsafeBytes(of: value.bigEndian) { Data($0) }
        }

        private static func littleEndian(_ value: UInt32) -> Data {
            withUnsafeBytes(of: value.littleEndian) { Data($0) }
        }

        private static func readLittleEndianU32(_ data: Data) -> UInt32 {
            let b = [UInt8](data)
            return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
        }
    }

    // MARK: Pairing offer (QR payload / PIN)

    /// What the Mac displays as a QR code; the Android app scans it.
    /// Two OTP candidates are offered: the full-strength QR OTP and a
    /// PIN-derived OTP (6-digit fallback typed on the phone).
    public struct PairingOffer: Equatable {
        public let macId: Data
        public let macName: String
        public let identityPub: Data
        public let qrOtp: Data
        public let pin: String

        public init(macId: Data, macName: String, identityPub: Data, qrOtp: Data, pin: String) {
            self.macId = macId
            self.macName = macName
            self.identityPub = identityPub
            self.qrOtp = qrOtp
            self.pin = pin
        }

        /// The OTP embedded in the QR payload.
        public var otp: Data { qrOtp }

        /// All acceptable OTPs, in preference order.
        public var otpCandidates: [Data] { [qrOtp, otpFromPin(pin)] }
    }

    public static func randomOTP() -> Data {
        AirPadCrypto.randomBytes(otpLength)
    }

    public static func randomPIN() -> String {
        String(format: "%06d", Int.random(in: 0...999_999))
    }

    /// QR payload: JSON. Scanned by the Android app (or replaced by the PIN).
    public static func encodeOfferQR(_ offer: PairingOffer) -> String {
        let json: [String: String] = [
            "v": "2",
            "t": "airpad",
            "name": offer.macName,
            "macId": offer.macId.base64EncodedString(),
            "key": offer.identityPub.base64EncodedString(),
            "otp": offer.qrOtp.base64EncodedString()
        ]
        let data = try! JSONSerialization.data(withJSONObject: json)
        return String(data: data, encoding: .utf8) ?? ""
    }

    public static func decodeOfferQR(_ text: String) -> PairingOffer? {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              json["t"] == "airpad",
              let macId = Data(base64: json["macId"] ?? ""), macId.count == deviceIdLength,
              let key = Data(base64: json["key"] ?? ""), key.count == publicKeyLength,
              let otp = Data(base64: json["otp"] ?? ""), otp.count == otpLength,
              let name = json["name"] else { return nil }
        return PairingOffer(macId: macId, macName: name, identityPub: key, qrOtp: otp, pin: "000000")
    }

    // MARK: Private helpers

    private static func encodeString(_ value: String) -> Data {
        let utf8 = Data(value.utf8.prefix(255))
        return Data([UInt8(utf8.count)]) + utf8
    }

    private static func decodeString(_ payload: Data, at offset: Int) -> String? {
        guard offset < payload.count else { return nil }
        let length = Int(payload[offset])
        let end = offset + 1 + length
        guard end <= payload.count else { return nil }
        return String(data: payload.subdata(in: (offset + 1)..<end), encoding: .utf8)
    }
}

extension Data {
    init?(base64: String) {
        self.init(base64Encoded: base64)
    }
}
