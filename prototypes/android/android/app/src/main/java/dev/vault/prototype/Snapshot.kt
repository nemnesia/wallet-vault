package dev.vault.prototype

import android.content.Context
import android.util.AtomicFile
import java.io.File
import org.json.JSONObject

internal fun requireInput(value: Boolean) { require(value) { "INVALID_INPUT" } }
internal fun validId(id: String) = id.matches(Regex("[0-9a-f]{32}"))
internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
internal fun unhex(value: String, max: Int): ByteArray {
    requireInput(value.length <= max * 2 && value.length % 2 == 0 && value.matches(Regex("[0-9a-f]*")))
    return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
internal data class KeyWrap(val id: String, val iv: String, val ciphertext: String) {
    fun json() = JSONObject().put("id", id).put("iv", iv).put("ciphertext", ciphertext)
    companion object {
        fun parse(v: JSONObject): KeyWrap {
            requireInput(v.keys().asSequence().toSet() == setOf("id", "iv", "ciphertext"))
            val wrap = KeyWrap(v.getString("id"), v.getString("iv"), v.getString("ciphertext"))
            requireInput(validId(wrap.id) && unhex(wrap.iv, 12).size == 12 && unhex(wrap.ciphertext, 48).size == 48)
            return wrap
        }
    }
}
internal data class Snapshot(val records: JSONObject, val profileWrap: KeyWrap, val signingWrap: KeyWrap) {
    val id: String get() = records.getString("id")
    val label: String get() = records.getString("label")
    fun json() = JSONObject(records.toString()).put("version", 1).put("profileWrap", profileWrap.json()).put("signingWrap", signingWrap.json())
    companion object {
        fun parse(v: JSONObject): Snapshot {
            requireInput(v.keys().asSequence().toSet() == setOf("version", "id", "label", "profileRecord", "signingRecord", "profileWrap", "signingWrap"))
            requireInput(v.getInt("version") == 1)
            val records = JSONObject(v.toString()).apply { remove("version"); remove("profileWrap"); remove("signingWrap") }
            requireInput(validId(records.getString("id")))
            NativeRust.call("validate", records)
            return Snapshot(records, KeyWrap.parse(v.getJSONObject("profileWrap")), KeyWrap.parse(v.getJSONObject("signingWrap")))
        }
    }
}
internal class SnapshotStore(context: Context) {
    private val directory = File(context.noBackupFilesDir, "profiles").apply { check(mkdirs() || isDirectory) { "STORAGE_FAILED" } }
    fun list(): List<Snapshot> = (directory.listFiles() ?: throw IllegalStateException("STORAGE_FAILED"))
        .filter { it.name.matches(Regex("[0-9a-f]{32}\\.json")) }.map { load(it.name.removeSuffix(".json")) }
    fun load(id: String): Snapshot {
        requireInput(validId(id))
        val file = AtomicFile(File(directory, "$id.json"))
        val bytes = file.openRead().use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) { val count = input.read(buffer); if (count < 0) break; check(out.size() + count <= 32768) { "INVALID_INPUT" }; out.write(buffer, 0, count) }
            out.toByteArray()
        }
        return Snapshot.parse(JSONObject(String(bytes, Charsets.UTF_8))).also { requireInput(it.id == id) }
    }
    fun save(snapshot: Snapshot, abort: Boolean) {
        val target = File(directory, "${snapshot.id}.json")
        check(!target.exists()) { "STORAGE_FAILED" }
        val bytes = snapshot.json().toString().toByteArray(Charsets.UTF_8)
        requireInput(bytes.size <= 32768)
        val file = AtomicFile(target)
        val output = file.startWrite()
        try {
            output.write(bytes)
            check(!abort) { "STORAGE_FAILED" }
            output.fd.sync()
            file.finishWrite(output)
        } catch (error: Exception) { file.failWrite(output); throw error }
    }
}
