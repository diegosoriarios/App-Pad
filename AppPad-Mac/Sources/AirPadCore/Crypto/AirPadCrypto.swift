import Foundation
import CryptoKit
import CommonCrypto

/// Low-level crypto primitives for the AirPad v2 secure transport.
/// HKDF-SHA256 (RFC 5869), HMAC-SHA256, AES-256-GCM, P-256 ECDH.
///
/// HKDF is implemented here (instead of CryptoKit's HKDF) so the Mac and the
/// Android app share one byte-exact derivation path that can be tested against
/// the RFC 5869 vectors on both platforms.
///
/// AES-GCM is implemented on top of CommonCrypto's AES block cipher with a
/// hand-rolled CTR/GHASH: this SDK's CryptoKit `AES.GCM.open` traps instead of
/// throwing on authentication failure, which would crash the app on the first
/// tampered or replayed packet. The implementation is verified against the
/// GCM spec / NIST test vectors in the unit tests.
enum AirPadCrypto {
    enum CryptoError: Error {
        case invalidCiphertext
        case invalidKey
        case authenticationFailed
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hmacSha256(key: Data, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: [UInt8](message), using: SymmetricKey(data: key)))
    }

    /// RFC 5869 HKDF with SHA-256.
    static func hkdfSha256(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
        let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        let prk = hmacSha256(key: effectiveSalt, message: ikm)

        var okm = Data()
        var previousBlock = Data()
        var counter: UInt8 = 1
        while okm.count < length {
            previousBlock = hmacSha256(key: prk, message: previousBlock + info + Data([counter]))
            okm.append(previousBlock)
            counter &+= 1
        }
        return okm.prefix(length)
    }

    /// P-256 ECDH shared secret (32 bytes, leading zeros preserved — matches
    /// Android's left-padded `KeyAgreement.generateSecret()`).
    static func ecdhP256(privateKey: P256.KeyAgreement.PrivateKey,
                         publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return secret.withUnsafeBytes { Data($0) }
    }

    /// AES-GCM seal (key: 16/24/32 bytes); returns ciphertext || tag(16).
    static func aesGcmSeal(key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> Data {
        guard [16, 24, 32].contains(key.count), nonce.count == 12 else { throw CryptoError.invalidKey }
        let result = AESGCM.seal(
            key: [UInt8](key), nonce: [UInt8](nonce),
            plaintext: [UInt8](plaintext), aad: [UInt8](aad)
        )
        return Data(result.ct) + Data(result.tag)
    }

    /// AES-GCM open; expects ciphertext || tag(16).
    static func aesGcmOpen(key: Data, nonce: Data, ciphertextAndTag: Data, aad: Data) throws -> Data {
        guard [16, 24, 32].contains(key.count), nonce.count == 12 else { throw CryptoError.invalidKey }
        guard ciphertextAndTag.count > 16 else { throw CryptoError.invalidCiphertext }
        let bytes = [UInt8](ciphertextAndTag)
        let ct = bytes.dropLast(16)
        let tag = bytes.suffix(16)
        guard let plain = AESGCM.open(
            key: [UInt8](key), nonce: [UInt8](nonce),
            ct: Array(ct), tag: Array(tag), aad: [UInt8](aad)
        ) else { throw CryptoError.authenticationFailed }
        return Data(plain)
    }

    /// Constant-time equality for MAC comparison.
    static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    /// Cryptographically secure random bytes.
    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess)
        return Data(bytes)
    }
}

/// AES-GCM (any AES key size CommonCrypto supports) over the raw block
/// cipher, per NIST SP 800-38D.
enum AESGCM {
    static func constantTimeEq(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    private static func encryptBlock(key: [UInt8], _ block: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        var outLen = 0
        let status = CCCrypt(
            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
            key, key.count, nil,
            block, block.count,
            &out, out.count, &outLen
        )
        precondition(status == kCCSuccess)
        return out
    }

    private static func xor16(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { r[i] = a[i] ^ b[i] }
        return r
    }

    private static func shiftRight(_ v: [UInt8]) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 {
            r[i] = v[i] >> 1
            if i > 0 { r[i] |= (v[i - 1] & 1) << 7 }
        }
        return r
    }

    /// GF(2^128) multiply, bit-serial (GCM spec Algorithm 1).
    private static func ghashMult(_ x: [UInt8], _ h: [UInt8]) -> [UInt8] {
        var z = [UInt8](repeating: 0, count: 16)
        var v = h
        for i in 0..<128 {
            if (x[i / 8] >> UInt8(7 - (i % 8))) & 1 == 1 {
                z = xor16(z, v)
            }
            let lsb = v[15] & 1
            v = shiftRight(v)
            if lsb == 1 { v[0] ^= 0xE1 }
        }
        return z
    }

    /// GHASH over zero-padded AAD and ciphertext plus the bit-length block.
    private static func ghash(h: [UInt8], aad: [UInt8], ct: [UInt8]) -> [UInt8] {
        var y = [UInt8](repeating: 0, count: 16)

        var a = aad
        while a.count % 16 != 0 { a.append(0) }
        var i = 0
        while i < a.count {
            y = ghashMult(xor16(y, Array(a[i..<i + 16])), h)
            i += 16
        }

        var c = ct
        while c.count % 16 != 0 { c.append(0) }
        i = 0
        while i < c.count {
            y = ghashMult(xor16(y, Array(c[i..<i + 16])), h)
            i += 16
        }

        var lenBlock = [UInt8](repeating: 0, count: 16)
        let aBits = UInt64(aad.count) * 8
        let cBits = UInt64(ct.count) * 8
        for shift in 0..<8 {
            lenBlock[7 - shift] = UInt8(truncatingIfNeeded: aBits >> (8 * UInt64(shift)))
            lenBlock[15 - shift] = UInt8(truncatingIfNeeded: cBits >> (8 * UInt64(shift)))
        }
        return ghashMult(xor16(y, lenBlock), h)
    }

    private static func inc32(_ block: [UInt8]) -> [UInt8] {
        var r = block
        var ctr: UInt32 = 0
        for i in 12..<16 { ctr = (ctr << 8) | UInt32(r[i]) }
        ctr = ctr &+ 1
        for i in 0..<4 { r[15 - i] = UInt8(truncatingIfNeeded: ctr >> (8 * UInt32(i))) }
        return r
    }

    static func seal(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) -> (ct: [UInt8], tag: [UInt8]) {
        precondition(nonce.count == 12)
        let h = encryptBlock(key: key, [UInt8](repeating: 0, count: 16))
        var j0 = nonce
        j0.append(contentsOf: [0, 0, 0, 1])

        var counter = inc32(j0)
        var ct = [UInt8]()
        ct.reserveCapacity(plaintext.count)
        var offset = 0
        while offset < plaintext.count {
            let keystream = encryptBlock(key: key, counter)
            let n = min(16, plaintext.count - offset)
            for i in 0..<n { ct.append(plaintext[offset + i] ^ keystream[i]) }
            offset += n
            counter = inc32(counter)
        }

        let s = ghash(h: h, aad: aad, ct: ct)
        let ej0 = encryptBlock(key: key, j0)
        return (ct, xor16(s, ej0))
    }

    static func open(key: [UInt8], nonce: [UInt8], ct: [UInt8], tag: [UInt8], aad: [UInt8]) -> [UInt8]? {
        precondition(nonce.count == 12)
        let h = encryptBlock(key: key, [UInt8](repeating: 0, count: 16))
        var j0 = nonce
        j0.append(contentsOf: [0, 0, 0, 1])

        let s = ghash(h: h, aad: aad, ct: ct)
        let ej0 = encryptBlock(key: key, j0)
        guard constantTimeEq(xor16(s, ej0), tag) else { return nil }

        var counter = inc32(j0)
        var pt = [UInt8]()
        pt.reserveCapacity(ct.count)
        var offset = 0
        while offset < ct.count {
            let keystream = encryptBlock(key: key, counter)
            let n = min(16, ct.count - offset)
            for i in 0..<n { pt.append(ct[offset + i] ^ keystream[i]) }
            offset += n
            counter = inc32(counter)
        }
        return pt
    }
}
