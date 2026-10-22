package dev.vault.prototype;
import java.util.Arrays;
public final class NativeRust {
    static { System.loadLibrary("vault_android"); }
    private native String command(String action,String data,byte[] secret);
    private native byte[] registrationKey(int purpose);
    private static String field(String json,String key) {
        var matcher=java.util.regex.Pattern.compile("\\\""+key+"\\\":\\\"([0-9a-f]+)\\\"").matcher(json);
        if(!matcher.find())throw new AssertionError("missing field");return matcher.group(1);
    }
    public static void main(String[] args) {
        var nativeRust=new NativeRust();
        String records=nativeRust.command("start","{\"label\":\"jni-smoke\"}",new byte[0]);
        byte[] profile=nativeRust.registrationKey(1),signing=nativeRust.registrationKey(2);
        try {
            nativeRust.command("cancel","{}",new byte[0]);
            String state=nativeRust.command("open",records,profile);
            if(!state.contains("unlocked"))throw new AssertionError("open failed");
            String request=field(nativeRust.command("prepare","{\"now\":10}",new byte[0]),"requestId");
            nativeRust.command("begin","{\"requestId\":\""+request+"\",\"now\":11}",new byte[0]);
            if(!nativeRust.command("finish","{\"now\":12}",signing).contains("true"))throw new AssertionError("probe failed");
            try {nativeRust.command("finish","{\"now\":13}",signing);throw new AssertionError("replay accepted");}
            catch(IllegalStateException expected){if(!expected.getMessage().equals("INVALID_STATE"))throw expected;}
            nativeRust.command("lock","{}",new byte[0]);
            if(!nativeRust.command("status","{}",new byte[0]).contains("locked"))throw new AssertionError("lock failed");
            System.out.println("PASS: actual JVM/JNI/Rust roundtrip, single-use rejection and lock (no Android biometric claim)");
        } finally {Arrays.fill(profile,(byte)0);Arrays.fill(signing,(byte)0);}
    }
}
