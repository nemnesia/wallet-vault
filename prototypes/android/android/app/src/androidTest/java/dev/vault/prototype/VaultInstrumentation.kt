package dev.vault.prototype

import android.app.Instrumentation
import android.app.Activity
import android.content.ContextWrapper
import android.os.Bundle
import java.io.File
import javax.crypto.IllegalBlockSizeException
import org.json.JSONObject

/** Explicitly invoked test APK only. No test entry point or DEK access in the application UI. */
class VaultInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); start() }
    override fun onStart() {
        val results = Bundle()
        var failed = false
        fun test(name: String, action: () -> Unit) {
            try { action();results.putString(name,"PASS") }
            catch (error: Exception) { failed = true;results.putString(name,"FAIL: ${error.javaClass.simpleName}") }
        }
        test("unauthenticated-keystore-encrypt-decrypt") {
            val adapter = KeyAdapter()
            val id = adapter.wrapId()
            try {
                adapter.create(id,1)
                val info = adapter.attributes(id,1)
                check(info.getBoolean("nonExportable") && info.getBoolean("authenticationRequired"))
                check(info.getInt("authenticationValiditySeconds") == 0)
                fun denied(prepared: AuthenticatedCipher) {
                    var rejected = false
                    try {
                        prepared.cipher.updateAAD(prepared.aad)
                        val output = prepared.cipher.doFinal(ByteArray(48))
                        output.fill(0)
                    } catch (_: IllegalBlockSizeException) { rejected = true }
                    check(rejected) { "Unauthenticated operation returned data" }
                }
                denied(adapter.encrypt(id,"instrumentation",1,adapter.wrapId()))
                denied(adapter.decrypt(id,"instrumentation",1,KeyWrap(adapter.wrapId(),"00".repeat(12),"00".repeat(48))))
            } finally { adapter.delete(id,1) }
        }
        test("atomic-store-abort-reload-overwrite-malformed") {
            val root = File(targetContext.cacheDir,"vault-test-${System.nanoTime()}")
            val isolated = object : ContextWrapper(targetContext) { override fun getNoBackupFilesDir() = root }
            val store = SnapshotStore(isolated)
            fun snapshot(): Snapshot {
                val records = NativeRust.call("start",JSONObject().put("label","storage-test"))
                NativeRust.call("cancel")
                val wrap = KeyWrap("01".repeat(16),"02".repeat(12),"03".repeat(48))
                return Snapshot(records,wrap,wrap)
            }
            try {
                NativeRust.call("lock")
                val first = snapshot(); store.save(first,false)
                val bytes = store.load(first.id).json().toString()
                val second = snapshot()
                var aborted = false
                try {store.save(second,true)} catch (_: IllegalStateException) {aborted = true}
                check(aborted && store.list().size == 1)
                check(SnapshotStore(isolated).load(first.id).json().toString() == bytes)
                var overwrite = false
                try {store.save(first,false)} catch (_: IllegalStateException) {overwrite = true}
                check(overwrite && store.load(first.id).json().toString() == bytes)
                File(root,"profiles/${second.id}.json").writeText("{}")
                var malformed = false
                try {store.list()} catch (_: Exception) {malformed = true}
                check(malformed)
                check(File(root,"profiles/${first.id}.json").exists())
            } finally {NativeRust.call("lock"); root.deleteRecursively()}
        }
        test("android-jni-single-use-expiry-lock") {
            NativeRust.call("lock")
            val records = NativeRust.call("start",JSONObject().put("label","android-jni-test"))
            val profile = NativeRust.registrationKey(1);val signing = NativeRust.registrationKey(2)
            fun rejects(code: String, action: () -> Unit) {
                var actual: String? = null
                try {action()} catch (error: IllegalStateException) {actual = error.message}
                check(actual == code)
            }
            try {
                NativeRust.call("cancel");NativeRust.call("open",records,profile)
                var id = NativeRust.call("prepare",JSONObject().put("now",10)).getString("requestId")
                val begin = JSONObject().put("requestId",id).put("now",11)
                NativeRust.call("begin",begin)
                rejects("BUSY") {NativeRust.call("begin",begin)}
                NativeRust.call("finish",JSONObject().put("now",12),signing)
                rejects("INVALID_STATE") {NativeRust.call("finish",JSONObject().put("now",13),signing)}
                id = NativeRust.call("prepare",JSONObject().put("now",20)).getString("requestId")
                rejects("EXPIRED") {NativeRust.call("begin",JSONObject().put("requestId",id).put("now",60020))}
                rejects("INVALID_STATE") {NativeRust.call("begin",JSONObject().put("requestId",id).put("now",60021))}
                NativeRust.call("lock")
                check(NativeRust.call("status").getString("state") == "locked")
                rejects("INVALID_STATE") {NativeRust.registrationKey(1)}
            } finally {profile.fill(0);signing.fill(0);NativeRust.call("lock")}
        }
        finish(if (failed) Activity.RESULT_CANCELED else Activity.RESULT_OK,results)
    }
}
