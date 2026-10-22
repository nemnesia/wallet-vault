package dev.vault.prototype

import org.json.JSONObject

// Internal JNI only. Never register DEK access as a ReactMethod.
internal object NativeRust {
    init { System.loadLibrary("vault_android") }
    external fun command(action: String, data: String, secret: ByteArray): String
    external fun registrationKey(purpose: Int): ByteArray
    fun call(action: String, data: JSONObject = JSONObject(), secret: ByteArray = byteArrayOf()): JSONObject =
        JSONObject(command(action, data.toString(), secret))
}
