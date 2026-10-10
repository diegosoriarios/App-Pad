package com.diego.apppad.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Low-level crypto primitives for the AirPad v2 secure transport.
 * Mirrors the Mac's `AirPadCrypto.swift` byte-for-byte:
 *  - HKDF-SHA256 (RFC 5869) with the same extract/expand layout
 *  - HMAC-SHA256 verify tags
 *  - AES-256-GCM (plaintext || tag(16), 12-byte nonce, AAD)
 *  - P-256 ECDH; shared secret = x-coordinate left-padded to 32 bytes,
 *    which is exactly what CryptoKit's `sharedSecretWith` produces.
 *
 * Public keys travel as x9.63 uncompressed points (0x04 || X || Y, 65 bytes),
 * the same encoding CryptoKit calls `x963Representation`.
 */
object AirPadCrypto {

    class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val random = SecureRandom()

    // MARK: - Hashes

    fun sha256(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /** RFC 5869 HKDF with SHA-256 (matches AirPadCrypto.hkdfSha256 on the Mac). */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmacSha256(effectiveSalt, ikm)

        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val input = ByteArray(previous.size + info.size + 1)
            previous.copyInto(input, 0)
            info.copyInto(input, previous.size)
            input[input.size - 1] = counter.toByte()
            previous = hmacSha256(prk, input)
            val n = minOf(previous.size, length - offset)
            previous.copyInto(out, offset, 0, n)
            offset += n
            counter++
        }
        return out
    }

    // MARK: - AES-GCM

    /** AES-GCM seal; returns ciphertext || tag(16). Key: 16/24/32 bytes. */
    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size in intArrayOf(16, 24, 32)) { "AES key must be 16/24/32 bytes" }
        require(nonce.size == 12) { "GCM nonce must be 12 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /** AES-GCM open; expects ciphertext || tag(16). Throws on authentication failure. */
    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.size in intArrayOf(16, 24, 32)) { "AES key must be 16/24/32 bytes" }
        require(nonce.size == 12) { "GCM nonce must be 12 bytes" }
        require(ciphertextAndTag.size > 16) { "ciphertext too short" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertextAndTag) // throws AEADBadTagException on tamper
    }

    // MARK: - P-256 ECDH

    data class EcKeyPair(val privateKey: java.security.PrivateKey, val publicKey: java.security.PublicKey)

    /** Fresh P-256 (secp256r1) key agreement pair. */
    fun generateEcKeyPair(): EcKeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"), random)
        val kp = generator.generateKeyPair()
        return EcKeyPair(kp.private, kp.public)
    }

    /**
     * ECDH shared secret: the x-coordinate, left-padded to 32 bytes.
     * Identical to CryptoKit's P-256 `sharedSecretFromKeyAgreement`.
     */
    fun ecdhP256(privateKey: java.security.PrivateKey, peerPublicKey: java.security.PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(peerPublicKey, true)
        return agreement.generateSecret()
    }

    /** Encodes an EC public key as x9.63 uncompressed: 0x04 || X || Y (65 bytes). */
    fun publicKeyToX963(publicKey: java.security.PublicKey): ByteArray {
        val ec = publicKey as java.security.interfaces.ECPublicKey
        val x = toFixed32(ec.w.affineX)
        val y = toFixed32(ec.w.affineY)
        val out = ByteArray(1 + 32 + 32)
        out[0] = 0x04
        x.copyInto(out, 1)
        y.copyInto(out, 33)
        return out
    }

    /** Decodes a 65-byte x9.63 uncompressed point into an EC PublicKey. */
    fun publicKeyFromX963(x963: ByteArray): java.security.PublicKey {
        require(x963.size == 65 && x963[0] == 0x04.toByte()) { "expected 65-byte x9.63 point" }
        val x = BigInteger(1, x963.copyOfRange(1, 33))
        val y = BigInteger(1, x963.copyOfRange(33, 65))
        val factory = KeyFactory.getInstance("EC")
        return factory.generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Params()))
    }

    /** Serializes a private key (PKCS#8) for storage. */
    fun privateKeyToStored(privateKey: java.security.PrivateKey): ByteArray =
        privateKey.encoded

    fun privateKeyFromStored(encoded: ByteArray): java.security.PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(encoded))

    /** Serializes a public key (X.509/SPKI); used only for our own keys. */
    fun publicKeyToStored(publicKey: java.security.PublicKey): ByteArray =
        publicKey.encoded

    fun publicKeyFromStored(encoded: ByteArray): java.security.PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))

    // MARK: - Helpers

    /** Constant-time equality for MAC comparison. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    /** Cryptographically secure random bytes. */
    fun randomBytes(count: Int): ByteArray = ByteArray(count).also { random.nextBytes(it) }

    private fun p256Params(): java.security.spec.ECParameterSpec {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        return (generator.generateKeyPair().public as java.security.interfaces.ECPublicKey).params
    }

    /** Big-endian, unsigned, exactly 32 bytes (strips or zero-pads the sign). */
    private fun toFixed32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size == 33 && raw[0].toInt() == 0 -> raw.copyOfRange(1, 33)
            raw.size > 32 -> throw CryptoException("coordinate longer than 32 bytes")
            else -> ByteArray(32 - raw.size) + raw
        }
    }
}
