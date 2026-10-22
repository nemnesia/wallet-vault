package dev.vault.prototype

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.os.Build
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

internal data class AuthenticatedCipher(val cipher: Cipher, val aad: ByteArray)

internal class KeyAdapter {
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val prefix = "vault.prototype.v1."
    fun alias(id: String, purpose: Int): String {
        requireInput(validId(id) && purpose in 1..2)
        return "$prefix$id.$purpose"
    }
    fun create(id: String, purpose: Int) {
        val name = alias(id, purpose)
        check(!keys.containsAlias(name)) { "INVALID_STATE" }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true).build())
        }.generateKey()
    }
    private fun key(id: String, purpose: Int): SecretKey =
        keys.getKey(alias(id, purpose), null) as? SecretKey ?: throw IllegalStateException("KEY_INVALIDATED")
    fun wrapId(): String = hex(ByteArray(16).also { SecureRandom().nextBytes(it) })
    private fun aad(id: String, label: String, purpose: Int, wrapId: String): ByteArray {
        val name = label.toByteArray(Charsets.UTF_8)
        return "vault-android/wrap/v1".toByteArray(Charsets.UTF_8) + unhex(id,16) + byteArrayOf(purpose.toByte()) +
            ByteBuffer.allocate(8).putInt(1).putInt(name.size).array() + name + unhex(wrapId,16)
    }
    fun encrypt(id: String, label: String, purpose: Int, wrapId: String): AuthenticatedCipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key(id,purpose))
            requireInput(iv.size == 12 && parameters.getParameterSpec(GCMParameterSpec::class.java).tLen == 128)
        }
        // updateAAD streams data to Keystore; defer it until CryptoObject authentication succeeds.
        return AuthenticatedCipher(cipher, aad(id,label,purpose,wrapId))
    }
    fun decrypt(id: String, label: String, purpose: Int, wrap: KeyWrap, alternateId: String? = null): AuthenticatedCipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE,key(alternateId ?: id,purpose),GCMParameterSpec(128,unhex(wrap.iv,12)))
        }
        return AuthenticatedCipher(cipher, aad(id,label,purpose,wrap.id))
    }
    fun delete(id: String, purpose: Int) { keys.deleteEntry(alias(id,purpose)) }
    fun cleanupUnreferenced(profiles: List<Snapshot>) {
        val keep = profiles.flatMap { listOf(alias(it.id,1),alias(it.id,2)) }.toSet()
        keys.aliases().toList().filter { it.matches(Regex("vault\\.prototype\\.v1\\.[0-9a-f]{32}\\.[12]")) && it !in keep }.forEach { keys.deleteEntry(it) }
    }
    fun attributes(id: String, purpose: Int): JSONObject {
        val value = key(id,purpose)
        val encoded = value.encoded
        if (encoded != null) { encoded.fill(0); throw IllegalStateException("INTERNAL_ERROR") }
        val info = SecretKeyFactory.getInstance(value.algorithm,"AndroidKeyStore").getKeySpec(value,KeyInfo::class.java) as KeyInfo
        @Suppress("DEPRECATION")
        val protection = if (Build.VERSION.SDK_INT >= 31) info.securityLevel.toString() else if (info.isInsideSecureHardware) "hardware" else "software"
        return JSONObject().put("purpose",purpose).put("nonExportable",true).put("securityLevel",protection)
            .put("authenticationRequired",info.isUserAuthenticationRequired)
            .put("authenticationValiditySeconds",info.userAuthenticationValidityDurationSeconds)
            .put("authenticationHardwareEnforced",info.isUserAuthenticationRequirementEnforcedBySecureHardware)
    }
}
