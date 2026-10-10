package com.diego.apppad.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AirPadCryptoTest {

    // RFC 5869 A.2 Test Case 1 (SHA-256)
    @Test
    fun testHkdfRfc5869Vector1() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c)
        val info = byteArrayOf(0xf0.toByte(), 0xf1.toByte(), 0xf2.toByte(), 0xf3.toByte(), 0xf4.toByte(), 0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(), 0xf8.toByte(), 0xf9.toByte())
        val okm = AirPadCrypto.hkdfSha256(ikm, salt, info, 42)
        val expected = byteArrayOf(
            0x3c.toByte(), 0xb2.toByte(), 0x5f.toByte(), 0x25.toByte(), 0xfa.toByte(), 0xac.toByte(), 0xd5.toByte(), 0x7a.toByte(), 0x90.toByte(), 0x43.toByte(), 0x4f.toByte(), 0x64.toByte(), 0xd0.toByte(), 0x36.toByte(), 0x2f.toByte(), 0x2a.toByte(),
            0x2d.toByte(), 0x2d.toByte(), 0x0a.toByte(), 0x90.toByte(), 0xcf.toByte(), 0x1a.toByte(), 0x5a.toByte(), 0x4c.toByte(), 0x5d.toByte(), 0xb0.toByte(), 0x2d.toByte(), 0x56.toByte(), 0xec.toByte(), 0xc4.toByte(), 0xc5.toByte(), 0xbf.toByte(),
            0x34.toByte(), 0x00.toByte(), 0x72.toByte(), 0x08.toByte(), 0xd5.toByte(), 0xb8.toByte(), 0x87.toByte(), 0x18.toByte(), 0x58.toByte(), 0x65.toByte()
        )
        assertTrue(okm.contentEquals(expected))
    }

    // NIST / McGrew-Viega AES-256-GCM vector: zero key, zero IV, 16 zero bytes
    @Test
    fun testAesGcmKnownVector() {
        val key = ByteArray(32)
        val nonce = ByteArray(12)
        val plaintext = ByteArray(16)
        val sealed = AirPadCrypto.aesGcmSeal(key, nonce, plaintext, ByteArray(0))
        assertTrue(sealed.copyOfRange(0, 16).contentEquals(byteArrayOf(
            0xce.toByte(), 0xa7.toByte(), 0x40.toByte(), 0x3d.toByte(), 0x4d.toByte(), 0x60.toByte(), 0x6b.toByte(), 0x6e.toByte(),
            0x07.toByte(), 0x4e.toByte(), 0xc5.toByte(), 0xd3.toByte(), 0xba.toByte(), 0xf3.toByte(), 0x9d.toByte(), 0x18.toByte()
        )))
        val opened = AirPadCrypto.aesGcmOpen(key, nonce, sealed, ByteArray(0))
        assertTrue(opened.contentEquals(plaintext))
    }

    @Test
    fun testAesGcmRejectsTamperedData() {
        val key = AirPadCrypto.randomBytes(32)
        val nonce = AirPadCrypto.randomBytes(12)
        val sealed = AirPadCrypto.aesGcmSeal(key, nonce, "hello".toByteArray(), byteArrayOf(1, 2, 3))
        val tampered = sealed.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        try {
            AirPadCrypto.aesGcmOpen(key, nonce, tampered, byteArrayOf(1, 2, 3))
            throw AssertionError("tampered ciphertext must not open")
        } catch (e: Exception) {
            // expected (AEADBadTagException)
        }
        try {
            AirPadCrypto.aesGcmOpen(key, nonce, sealed, byteArrayOf(9, 9, 9))
            throw AssertionError("wrong AAD must not open")
        } catch (e: Exception) {
            // expected
        }
    }

    @Test
    fun testEcdhBothOrdersMatch() {
        val a = AirPadCrypto.generateEcKeyPair()
        val b = AirPadCrypto.generateEcKeyPair()
        val ab = AirPadCrypto.ecdhP256(a.privateKey, b.publicKey)
        val ba = AirPadCrypto.ecdhP256(b.privateKey, a.publicKey)
        assertTrue(ab.contentEquals(ba))
        assertEquals(32, ab.size)
    }

    @Test
    fun testX963RoundTrip() {
        val pair = AirPadCrypto.generateEcKeyPair()
        val x963 = AirPadCrypto.publicKeyToX963(pair.publicKey)
        assertEquals(65, x963.size)
        assertEquals(0x04, x963[0].toInt() and 0xFF)
        val decoded = AirPadCrypto.publicKeyFromX963(x963)
        assertTrue(
            AirPadCrypto.publicKeyToX963(decoded).contentEquals(x963)
        )
    }

    @Test
    fun testConstantTimeEquals() {
        assertTrue(AirPadCrypto.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertFalse(AirPadCrypto.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertFalse(AirPadCrypto.constantTimeEquals(byteArrayOf(1, 2), byteArrayOf(1, 2, 3)))
    }
}
