package com.nilvpn

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Private Rust-to-native secure-vault bridge. No WebView capability grants these commands: the
 * Tauri Rust core alone holds the PluginHandle. The AES key is generated inside Android Keystore,
 * is non-exportable, and is used only to seal/open the versioned vault envelope.
 */
@TauriPlugin
class NilSecureStorePlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun seal(invoke: Invoke) {
        val args = invoke.parseArgs(CryptoArgs::class.java)
        var plaintext: ByteArray? = null
        var aad: ByteArray? = null
        try {
            plaintext = decodeBounded(args.data, MAX_PLAINTEXT)
            aad = decodeBounded(args.aad, MAX_AAD)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, loadOrCreateKey())
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            check(iv.size == NONCE_LEN) { "unexpected GCM nonce length" }
            val envelope = ByteArray(HEADER.size + NONCE_LEN + ciphertext.size)
            HEADER.copyInto(envelope)
            iv.copyInto(envelope, HEADER.size)
            ciphertext.copyInto(envelope, HEADER.size + NONCE_LEN)
            invoke.resolve(JSObject().apply {
                put("data", Base64.encodeToString(envelope, Base64.NO_WRAP))
            })
            envelope.fill(0)
            ciphertext.fill(0)
            iv.fill(0)
        } catch (_: Throwable) {
            invoke.reject("secure storage operation failed")
        } finally {
            plaintext?.fill(0)
            aad?.fill(0)
        }
    }

    @Command
    fun open(invoke: Invoke) {
        val args = invoke.parseArgs(CryptoArgs::class.java)
        var envelope: ByteArray? = null
        var aad: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            envelope = decodeBounded(args.data, MAX_ENVELOPE)
            aad = decodeBounded(args.aad, MAX_AAD)
            require(envelope.size >= HEADER.size + NONCE_LEN + TAG_LEN)
            require(envelope.copyOfRange(0, HEADER.size).contentEquals(HEADER))
            val key = loadExistingKey()
                ?: throw IllegalStateException("secure storage key is unavailable")
            val nonce = envelope.copyOfRange(HEADER.size, HEADER.size + NONCE_LEN)
            val ciphertext = envelope.copyOfRange(HEADER.size + NONCE_LEN, envelope.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(aad)
            plaintext = cipher.doFinal(ciphertext)
            invoke.resolve(JSObject().apply {
                put("data", Base64.encodeToString(plaintext, Base64.NO_WRAP))
            })
            nonce.fill(0)
            ciphertext.fill(0)
        } catch (_: Throwable) {
            // Authentication failure, missing key, corrupt envelope, and KeyStore failure are all
            // intentionally indistinguishable to callers. Never replace an undecryptable vault.
            invoke.reject("secure storage operation failed")
        } finally {
            envelope?.fill(0)
            aad?.fill(0)
            plaintext?.fill(0)
        }
    }

    @Command
    fun destroyKey(invoke: Invoke) {
        try {
            val store = keyStore()
            if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS)
            invoke.resolve()
        } catch (_: Throwable) {
            invoke.reject("secure storage operation failed")
        }
    }

    private fun loadExistingKey(): SecretKey? {
        val store = keyStore()
        return (store.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    private fun loadOrCreateKey(): SecretKey {
        loadExistingKey()?.let { return it }
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(builder.build())
            generateKey()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun decodeBounded(value: String, max: Int): ByteArray {
        require(value.length <= ((max + 2) / 3) * 4 + 4)
        return Base64.decode(value, Base64.NO_WRAP).also { require(it.size <= max) }
    }

    class CryptoArgs {
        lateinit var data: String
        lateinit var aad: String
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.nilvpn.client.secure-vault.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val NONCE_LEN = 12
        private const val TAG_BITS = 128
        private const val TAG_LEN = TAG_BITS / 8
        private const val MAX_PLAINTEXT = 8 * 1024 * 1024
        private const val MAX_ENVELOPE = MAX_PLAINTEXT + 128
        private const val MAX_AAD = 256
        private val HEADER = byteArrayOf(0x4e, 0x49, 0x4c, 0x41, 0x01) // "NILA", v1
    }
}
