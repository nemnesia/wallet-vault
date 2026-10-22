package dev.vault.prototype

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.os.Build
import com.facebook.react.bridge.*
import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import java.time.Instant

class VaultModule(private val context: ReactApplicationContext) : ReactContextBaseJavaModule(context), LifecycleEventListener {
    private val main = Handler(Looper.getMainLooper())
    private val gate = OperationGate()
    private val store by lazy { SnapshotStore(context) }
    private val keys by lazy { KeyAdapter() }
    private var foreground = false
    private var selected: Snapshot? = null
    private var requestId: String? = null
    private val events = ArrayDeque<JSONObject>()
    private var operation: Operation? = null
    private var initialized = false
    private data class Operation(val token: OperationGate.Token, val promise: Promise,
        val created: MutableList<Pair<String,Int>> = mutableListOf(),var committed: Boolean = false,
        var signal: CancellationSignal? = null, var timer: Runnable? = null)
    init { context.addLifecycleEventListener(this) }
    override fun getName() = "VaultPrototype"
    private fun event(stage: String) {
        events.addLast(JSONObject().put("time",Instant.now().toString()).put("stage",stage))
        while(events.size > 200) events.removeFirst()
    }
    private fun ensureReady() {
        if (!initialized) {
            NativeRust.call("lock")
            // Abort cleanup if any committed snapshot is malformed; never infer which saved keys to delete.
            try { keys.cleanupUnreferenced(store.list()) } catch (_: Exception) { event("起動時の未参照鍵整理を中止。保存状態を確認してください") }
            initialized = true
        }
    }
    private fun code(error: Exception): String = when(error) {
        is KeyPermanentlyInvalidatedException -> "KEY_INVALIDATED"
        is AEADBadTagException -> "INTEGRITY_FAILED"
        is java.io.IOException -> "STORAGE_FAILED"
        is org.json.JSONException -> "INVALID_INPUT"
        else -> error.message?.takeIf { it in setOf("UNSUPPORTED","CANCELLED","EXPIRED","AUTH_NOT_COMPLETED","KEY_INVALIDATED","INTEGRITY_FAILED","INVALID_INPUT","INVALID_STATE","BUSY","STORAGE_FAILED","RANDOM_FAILED","INTERNAL_ERROR") } ?: "INTERNAL_ERROR"
    }
    private fun run(promise: Promise, action: () -> Unit) {
        main.post { try { ensureReady(); action() } catch(error: Exception) { promise.reject(code(error),code(error)) } }
    }
    private fun current(op: Operation) = operation === op && gate.current(op.token)
    private fun checkCurrent(op: Operation) { check(current(op)) { "CANCELLED" } }
    private fun clearCeremony(op: Operation) { op.timer?.let { main.removeCallbacks(it) }; op.timer = null; op.signal = null }
    private fun cleanCreated(op: Operation) { if (!op.committed) op.created.forEach { (id,purpose) -> try { keys.delete(id,purpose) } catch (_: Exception) { event("未参照鍵の整理は次回起動時に再試行します") } } }
    private fun finish(op: Operation) {
        if (!current(op)) return
        val result = statusJson().put("busy",false)
        clearCeremony(op); gate.finish(op.token); operation = null
        op.promise.resolve(result.toString())
    }
    private fun fail(op: Operation, reason: String) {
        if (!current(op)) return
        val signal = op.signal
        clearCeremony(op); gate.cancel(); operation = null
        NativeRust.call("cancel"); requestId = null; cleanCreated(op)
        event(reason); signal?.cancel(); op.promise.reject(reason,reason)
    }
    private fun requireBiometric() {
        check(context.getSystemService(BiometricManager::class.java).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) { "UNSUPPORTED" }
    }
    private fun start(promise: Promise): Operation {
        check(foreground && context.currentActivity != null) { "INVALID_STATE" }
        return Operation(gate.start(),promise).also { operation = it }
    }
    private fun authentic(op: Operation, title: String, prepared: AuthenticatedCipher, input: () -> ByteArray, result: (ByteArray) -> Unit) {
        checkCurrent(op)
        val cipher = prepared.cipher
        val activity = context.currentActivity ?: throw IllegalStateException("INVALID_STATE")
        val manager = context.getSystemService(BiometricManager::class.java)
        check(manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) { "UNSUPPORTED" }
        val signal = CancellationSignal(); op.signal = signal
        val started = SystemClock.elapsedRealtime()
        val timeout = Runnable { fail(op,"EXPIRED") };op.timer = timeout;main.postDelayed(timeout,60000)
        event("$title: 新規の強い生体認証待ち")
        val prompt = BiometricPrompt.Builder(activity).setTitle(title)
            .setSubtitle("検証用データ・認証付き鍵操作")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .setNegativeButton("取消",context.mainExecutor) { _,_ -> fail(op,"CANCELLED") }.build()
        prompt.authenticate(BiometricPrompt.CryptoObject(cipher),signal,context.mainExecutor,object: BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(value: BiometricPrompt.AuthenticationResult) {
                if (!current(op)) return
                clearCeremony(op)
                var step = "認証結果確認"
                try {
                    check(SystemClock.elapsedRealtime()-started < 60000) { "EXPIRED" }
                    check(value.cryptoObject?.cipher === cipher) { "INVALID_INPUT" }
                    step = "認証付きAAD設定"
                    cipher.updateAAD(prepared.aad)
                    step = "Native入力取得"
                    val plain = input()
                    step = "認証付きCipher操作"
                    val output = try { cipher.doFinal(plain) } finally { plain.fill(0) }
                    step = "認証後の結果処理"
                    try { checkCurrent(op); event("$title: 認証に結合した鍵操作が成功"); result(output) } finally { output.fill(0) }
                } catch(error: Exception) {
                    event("$title: $step 失敗 (${error.javaClass.simpleName})")
                    fail(op,code(error))
                }
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val reason = when(errorCode) {
                    BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, BiometricPrompt.BIOMETRIC_ERROR_CANCELED -> "CANCELLED"
                    BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT -> "EXPIRED"
                    BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS, BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT -> "UNSUPPORTED"
                    else -> "AUTH_NOT_COMPLETED"
                }; fail(op,reason)
            }
            override fun onAuthenticationFailed() { fail(op,"AUTH_NOT_COMPLETED") }
        })
    }
    private fun statusJson(): JSONObject {
        val result = NativeRust.call("status")
        result.put("busy",gate.busy).put("requestId",requestId ?: JSONObject.NULL)
        result.put("profiles",JSONArray(store.list().map { JSONObject().put("id",it.id).put("label",it.label).put("unlockMethod","os-biometric") }))
        result.put("events",JSONArray(events.toList()))
        result.put("environment",JSONObject().put("model",Build.MODEL).put("manufacturer",Build.MANUFACTURER)
            .put("sdk",Build.VERSION.SDK_INT).put("release",Build.VERSION.RELEASE).put("build",Build.DISPLAY)
            .put("canAuthenticateStrong",context.getSystemService(BiometricManager::class.java).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG))
            .put("applicationId",context.packageName).put("version","0.0.1").put("authentication","BIOMETRIC_STRONG / auth-per-use; PIN fallbackなし"))
        return result
    }
    @ReactMethod fun status(promise: Promise) = run(promise) { promise.resolve(statusJson().toString()) }
    @ReactMethod fun register(label: String, abortSave: Boolean, promise: Promise) = run(promise) {
        check(!gate.busy) { "BUSY" };check(selected == null) { "INVALID_STATE" }
        requireInput(label.toByteArray(Charsets.UTF_8).size in 1..64)
        val op = start(promise)
        try {
            requireBiometric()
            val records = NativeRust.call("start",JSONObject().put("label",label));val id = records.getString("id")
            for (purpose in 1..2) { keys.create(id,purpose); op.created.add(id to purpose) }
            val firstId = keys.wrapId(); val first = keys.encrypt(id,label,1,firstId)
            authentic(op,"Profile 鍵の登録",first,{ NativeRust.registrationKey(1) }) { output ->
                val profileWrap = KeyWrap(firstId,hex(first.cipher.iv),hex(output))
                val secondId = keys.wrapId();val second = keys.encrypt(id,label,2,secondId)
                authentic(op,"Signing 鍵の登録",second,{ NativeRust.registrationKey(2) }) { wrapped ->
                    val snapshot = Snapshot(records,profileWrap,KeyWrap(secondId,hex(second.cipher.iv),hex(wrapped)))
                    store.save(snapshot,abortSave);op.committed = true
                    NativeRust.call("lock"); event("暗号化保存コミット完了。locked")
                    event("Profile鍵属性: ${keys.attributes(id,1)}");event("Signing鍵属性: ${keys.attributes(id,2)}")
                    finish(op)
                }
            }
        } catch(error: Exception) { fail(op,code(error)) }
    }
    @ReactMethod fun open(id: String, mode: String, promise: Promise) = run(promise) {
        check(!gate.busy) { "BUSY" };check(selected == null) { "INVALID_STATE" }
        requireInput(mode in setOf("normal","tamper","wrong-key"))
        val op = start(promise)
        try {
            val snapshot = store.load(id)
            if (mode == "tamper") {
                val copy = unhex(snapshot.records.getString("profileRecord"),4096)
                copy[copy.lastIndex] = (copy.last().toInt() xor 1).toByte();snapshot.records.put("profileRecord",hex(copy))
            }
            val alternate = if (mode == "wrong-key") store.list().firstOrNull { it.id != id }?.id ?: throw IllegalStateException("INVALID_STATE") else null
            val cipher = keys.decrypt(id,snapshot.label,1,snapshot.profileWrap,alternate)
            authentic(op,"Profile 解除",cipher,{ unhex(snapshot.profileWrap.ciphertext,48) }) { key ->
                NativeRust.call("open",snapshot.records,key);selected = snapshot
                event("RustでProfile復号・tag検証が成功。unlocked");event("Profile鍵属性: ${keys.attributes(id,1)}");finish(op)
            }
        } catch(error: Exception) { fail(op,code(error)) }
    }
    @ReactMethod fun prepare(promise: Promise) = run(promise) {
        check(!gate.busy) { "BUSY" };check(selected != null) { "INVALID_STATE" }
        requestId = NativeRust.call("prepare",JSONObject().put("now",SystemClock.elapsedRealtime())).getString("requestId")
        event("一回限り要求を準備（60秒）");promise.resolve(statusJson().toString())
    }
    @ReactMethod fun execute(id: String, promise: Promise) = run(promise) {
        check(!gate.busy) { "BUSY" };check(requestId == id && selected != null) { "INVALID_STATE" }
        val snapshot = selected!!;val op = start(promise);requestId = null
        try {
            NativeRust.call("begin",JSONObject().put("requestId",id).put("now",SystemClock.elapsedRealtime()))
            val cipher = keys.decrypt(snapshot.id,snapshot.label,2,snapshot.signingWrap)
            authentic(op,"Signing データ照合",cipher,{ unhex(snapshot.signingWrap.ciphertext,48) }) { key ->
                NativeRust.call("finish",JSONObject().put("now",SystemClock.elapsedRealtime()),key)
                event("RustでSigningデータ復号・照合成功（実署名ではありません）。unlocked");finish(op)
            }
        } catch(error: Exception) { fail(op,code(error)) }
    }
    private fun stop(lock: Boolean) {
        val op = operation
        if (op != null) fail(op,"CANCELLED") else { gate.cancel();NativeRust.call("cancel");requestId = null }
        if (lock) { NativeRust.call("lock");selected = null;event("Sessionを破棄。locked") }
    }
    @ReactMethod fun cancel(promise: Promise) = run(promise) { stop(false);promise.resolve(statusJson().toString()) }
    @ReactMethod fun lock(promise: Promise) = run(promise) { stop(true);promise.resolve(statusJson().toString()) }
    @ReactMethod fun deleteSigningKey(promise: Promise) = run(promise) {
        check(!gate.busy) { "BUSY" };val snapshot = selected ?: throw IllegalStateException("INVALID_STATE")
        keys.delete(snapshot.id,2);NativeRust.call("cancel");requestId = null
        event("検証用Signing保護鍵を削除。今後の照合は失敗し、復旧できません")
        promise.resolve(statusJson().toString())
    }
    override fun onHostResume() { foreground = true }
    override fun onHostPause() { foreground = false;main.post { if (initialized) stop(true) } }
    override fun onHostDestroy() { foreground = false;main.post { if (initialized) stop(true) } }
    override fun invalidate() { context.removeLifecycleEventListener(this); main.post { if (initialized) stop(true) };super.invalidate() }
}
