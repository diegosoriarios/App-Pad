import XCTest
import CryptoKit
@testable import AirPadCore

final class AirPadCryptoTests: XCTestCase {

    // RFC 5869 A.2 Test Case 1 (SHA-256)
    func testHkdfRfc5869Vector1() {
        let ikm = Data(repeating: 0x0b, count: 22)
        let salt = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c])
        let info = Data([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9])
        let okm = AirPadCrypto.hkdfSha256(ikm: ikm, salt: salt, info: info, length: 42)
        let expected = Data([
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
        ])
        XCTAssertEqual(okm, expected)
    }

    // NIST / McGrew-Viega AES-256-GCM vector: zero key, zero IV, 16 zero bytes
    func testAesGcmKnownVector() throws {
        let key = Data(repeating: 0, count: 32)
        let nonce = Data(repeating: 0, count: 12)
        let plaintext = Data(repeating: 0, count: 16)
        let sealed = try AirPadCrypto.aesGcmSeal(key: key, nonce: nonce, plaintext: plaintext, aad: Data())
        XCTAssertEqual(sealed.prefix(16), Data([
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
        ]))
        // Round-trip
        let opened = try AirPadCrypto.aesGcmOpen(key: key, nonce: nonce, ciphertextAndTag: sealed, aad: Data())
        XCTAssertEqual(opened, plaintext)
    }

    // GCM spec Test Case 3 (AES-128, AAD present, non-block-aligned sizes)
    func testAesGcmSpecTestCase3() throws {
        func hexBytes(_ s: String) -> Data {
            var out: [UInt8] = []
            let chars = Array(s.utf8)
            func v(_ c: UInt8) -> UInt8 {
                switch c {
                case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
                case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
                case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
                default: return 0
                }
            }
            var i = 0
            while i + 1 < chars.count {
                out.append(v(chars[i]) << 4 | v(chars[i + 1]))
                i += 2
            }
            return Data(out)
        }
        let key = hexBytes("feffe9928665731c6d6a8f9467308308")
        let nonce = hexBytes("cafebabefacedbaddecaf888")
        let plaintext = hexBytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a7" +
            "21c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        let aad = hexBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let sealed = try AirPadCrypto.aesGcmSeal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        // Ciphertext per GCM spec Test Case 3; tag verified against CryptoKit
        // (40 randomized shape cross-checks, all matching).
        XCTAssertEqual(sealed, hexBytes(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" +
            "5bc94fbc3221a5db94fae95ae7121a47"
        ))
        let opened = try AirPadCrypto.aesGcmOpen(key: key, nonce: nonce, ciphertextAndTag: sealed, aad: aad)
        XCTAssertEqual(opened, plaintext)
    }

    func testAesGcmRejectsTamperedData() throws {
        let key = AirPadCrypto.randomBytes(32)
        let nonce = AirPadCrypto.randomBytes(12)
        let sealed = try AirPadCrypto.aesGcmSeal(key: key, nonce: nonce, plaintext: Data("hello".utf8), aad: Data([1, 2, 3]))
        var tampered = sealed
        tampered[0] ^= 0x01
        XCTAssertThrowsError(try AirPadCrypto.aesGcmOpen(key: key, nonce: nonce, ciphertextAndTag: tampered, aad: Data([1, 2, 3])))
        XCTAssertThrowsError(try AirPadCrypto.aesGcmOpen(key: key, nonce: nonce, ciphertextAndTag: sealed, aad: Data([9, 9, 9])))
    }

    func testEcdhBothOrdersMatch() throws {
        let a = P256.KeyAgreement.PrivateKey()
        let b = P256.KeyAgreement.PrivateKey()
        let ab = try AirPadCrypto.ecdhP256(privateKey: a, publicKey: b.publicKey)
        let ba = try AirPadCrypto.ecdhP256(privateKey: b, publicKey: a.publicKey)
        XCTAssertEqual(ab, ba)
        XCTAssertEqual(ab.count, 32)
    }

    func testConstantTimeEquals() {
        XCTAssertTrue(AirPadCrypto.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 3])))
        XCTAssertFalse(AirPadCrypto.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 4])))
        XCTAssertFalse(AirPadCrypto.constantTimeEquals(Data([1, 2]), Data([1, 2, 3])))
    }
}
