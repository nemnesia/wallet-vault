# Android / OS保護鍵 × Native Rust プロトタイプ

Android Keystore の用途別AES鍵を、生体認証ごとの暗号操作で利用し、Rustで暗号化した検証データを
保存・再認証して復号する実験用アプリです。React Nativeの画面へDEKや平文は返しません。
モバイルのPasskey PRFではなく、Keystore + BiometricPromptを確認します。

[基本設計](../../../vault-docs/docs/prototypes/mobile-design.md)と
[実装仕様](../../../vault-docs/docs/prototypes/android-implementation.md)が根拠です。
検証後に削除予定であり、コード・依存・Nativeライブラリ・テストはこのディレクトリに閉じています。
結果は製品仕様へ引き継ぐまで保持します。iPhoneは未実装です。

## 対象端末と準備

- Android 11 / API 30 以上のarm64-v8a実機。強い生体認証（BIOMETRIC_STRONG）を登録してください。
  初回APKはarm64-v8aと補助検証用x86_64に対応し、32bit ARMは含みません。
- 指紋や顔認証があっても、弱い生体認証だけの機器は非対応です。PINへ自動切替しません。
- Node.js 24以上、Rust/Cargo、JDK 17、Android SDK platform 36・build-tools 36.0.0、NDK 27.1.12297006。
- ANDROID_HOMEをSDKディレクトリに、JAVA_HOMEをJDKへ設定し、platform-toolsのadbをPATHへ追加します。
  NDKを別配置する場合はANDROID_NDK_HOMEを設定します。

Windowsの場合、通常のSDK配置は `%LOCALAPPDATA%\Android\Sdk` です。
JDKとRustはそのWindows環境にも必要です。LinuxでビルドしたAPKを実機へ転送しても確認できます。
端末で開発者向けオプションとUSBデバッグを有効にし、接続時の確認を許可してください。

```sh
cd vault/prototypes/android
rustup target add aarch64-linux-android x86_64-linux-android
npm ci --ignore-scripts
npm run build
adb devices
npm run install:android
adb shell am start -n dev.vault.prototype/.MainActivity
```

APKは `android/app/build/outputs/apk/release/app-release.apk` です。
開発用debug署名ですが、JSを同梱したrelease variantのためMetroサーバは不要です。
このPoCの署名鍵を製品公開に使用しないでください。

WindowsでもNodeの同じビルド入口を使用します。スクリプトはホストOSに合わせてGradle wrapperとNDKを選択します。
Android Studioで作業する場合も、先に `npm run build:rust` でJNIライブラリを生成してください。

## 実機で確認する手順

1. アプリを開き、モデル・OS/build・認証方式を確認します。canAuthenticateStrong=0は利用可能を示します。
2. 検証用のProfile名で「生体認証して登録・保存」。Profile用・Signing用の2回の認証付き鍵操作を進めます。
3. 保存成功後がlockedで、一覧に残ることを確認します。
4. アプリを終了して開き直し、「再認証してProfileを復号」でunlockedになることを確認します。
5. unlockedのまま「要求を準備 → Signingデータを照合」を2回行い、毎回本人認証が出ることを確認します。
6. 「非秘密の結果を共有」で環境・状態・観測ログを保存し、実際の認証方法と目視結果を記録します。

Profile用OS鍵の解除と、Signing用OS鍵の操作は分離しています。
Signingデータ照合は実際のSymbol/NEM署名ではありません。

## 失敗時の確認

- **保存途中abort**：チェックを付けて新規登録。STORAGE_FAILEDとなり、一覧に部分Profileが残らないことを確認します。完了後はチェックを外します。
- **取消**：認証中に取消ボタンやシステムの取消を使います。Profile解除ならlocked、照合ならProfileはunlockedのままで要求が無効になります。
- **期限**：Profile認証を60秒放置するとEXPIRED・locked。要求準備後に65秒待って実行するとEXPIRED・unlockedです。
- **改ざんコピー**：lockedで実行します。実データは変更せず、Rustの完全性検証に失敗することを確認します。
- **別のOS鍵**：2件登録してからlockedで実行します。もう一方のProfileの保護鍵を使い、認証後にINTEGRITY_FAILEDとなることを確認します。
- **lock / background**：認証中や解除中にロック・ホームへの移動・Activity再生成を試し、古い応答で解除が復活しないことを確認します。
- **鍵削除**：解除後に「検証用Signing鍵を削除」を明示的に確認して実行します。その後の照合はKEY_INVALIDATEDとなります。復旧できません。
- **生体登録変更・端末ロック変更**：OS設定を変更したときの実際の鍵失効を、設定とともに別途記録します。鍵削除テストで代用した扱いにはしません。

OS鍵はアプリへエクスポートしません。解除されたDEKはJNI/Kotlin内を一時的に通り、Rustへ渡します。
使用後はクリアしますが、GC・JNI・暗号providerの全コピーの完全消去は保証しません。
非エクスポート性とhardware保護は別です。鍵属性ログのsecurityLevelや認証属性も記録してください。
OSの認証画面の表示だけをもって、hardwareでの鍵利用制約まで証明できたとはしません。

## 自動検証

```sh
npm run check
npm test
npm run build
```

checkはTypeScript・Rust format・Clippy、testはRustテスト・実JVM/JNI接続・AndroidのOperationGate単体テストを実行します。
実JVM/JNIテストにはjava/javacも必要です。デスクトップJVMと実AndroidのKeystore検証は別です。
APKの生成と実機での生体認証成功も分けて記録します。

Android OS上の直接検証には、別のテストAPKを使います（検証用アプリのみ）。
生体情報を登録した端末またはエミュレータを接続して実行します。

```sh
node scripts/gradle.mjs assembleDebug assembleDebugAndroidTest
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb install -r android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w dev.vault.prototype.test/dev.vault.prototype.VaultInstrumentation
```

3項目すべて`PASS`、`INSTRUMENTATION_CODE: -1`を確認します。コマンドの終了コードだけでは判定しません。
未認証Keystore操作の拒否、隔離ディレクトリでのAtomicFile保存中断・再読込・上書き拒否・破損拒否、
Android JNIでの重複実行・期限・lockを検証します。専用一時鍵と保存ファイルは後始末し、JNI状態をlockします。
アプリの検証データ消去や保護設定変更は行いません。

実機は未接続のため、Keystoreの実機保護レベル、認証ごとの鍵操作、失効、background挙動はNOT RUNです。
2026-10-22の確認結果：TypeScript・Rust format/Clippy、Rust 4件、Kotlin 2件、
実JVM/JNIラウンドトリップ、arm64-v8a/x86_64のNative生成、release APKビルドは成功しました。
Rustライブラリの16KB LOAD alignmentとAPKの同梱ライブラリも確認しました。
WSL内の補助エミュレータはKVMなしで起動が完了しませんでした。
その後、ユーザーがWindows側で起動したAndroid 16 / API 36・16KB pageのx86_64エミュレータへ
Windows版ADBの専用ポート5038で接続し、APKインストール・アプリ起動・Native環境表示を確認しました。
初回のcanAuthenticateStrongは11（生体情報未登録）でした。指紋登録後は0となりました。

2026-10-22のエミュレータ補助検証で、認証前の`updateAAD`が後続の`doFinal`を
`IllegalBlockSizeException`で失敗させる問題を確認し、AAD設定をCryptoObject認証成功後へ移しました。
修正後、正常系に加えて取消・誤認証・両用途の60秒期限・要求期限・保存abort・改ざん・別鍵・
background・Activity再生成・プロセス終了・Signing鍵削除・生体情報追加/一部削除・PIN変更をAVDで検証しました。
AndroidテストAPKの3項目もPASSです。詳細とSHA-256付き証跡は
[エミュレータ検証結果](../../../vault-docs/docs/prototypes/results/2026-10-22-android-emulator.md)に保持します。
指紋入力は模擬入力であり、物理端末での成功とは区別します。
鍵属性はsecurityLevel=0（software）、authenticationRequired=true、validitySeconds=0、
authenticationHardwareEnforced=falseでした。実機のハードウェア保護と、OSの明示的なlockout通知は未実証です。
全指紋削除・画面ロック無効化・強制PINリセットの組合せも未実施です。

失効試験により、AVD上の最初の2件のProfileは解除できません。
追加後の3件目（ID先頭`3AFFEA09`）は利用でき、検証終了時はこれを選択してlockedにしています。
アプリを再起動すると一覧の先頭が選択されるため、再開時は対象を選び直してください。
物理端末では検証専用の新しいProfileで再確認します。

依存監査では、RN/Metro/CLIのbraces由来の未修正指摘が20件（high、依存経路を含む）あります。
固定したbraces 3.0.3に修正版がなく、互換性を壊す旧RNへの自動downgradeはしていません。
これは製品公開の依存確認を完了した実装ではありません。Babel coreの修正可能な指摘は7.29.7へ更新しています。

## 構成・撤去

- `src/`：操作と非秘密結果だけを扱うReact Native画面。
- `android/`：Keystore、BiometricPrompt、AtomicFile、Native操作・ライフサイクルとJNI呼出し。
- `rust/`：独立DEK・検証データ、AES-GCM、固定snapshot、一回限り要求、JNI境界。
- `scripts/`：クロスビルド、APK生成、実JVM/JNI接続、インストール。

形式はプロトタイプ専用でChromeとの互換性はありません。データの移行・復旧・バックアップ・更新競合・Passwordは未実装です。
アプリバックアップは無効、保存先はnoBackupFilesDirで、認証状態や鍵平文を保存しません。

初回起動ではcommit済みsnapshotを読み、このPoCだけのprefixに属する未参照OS鍵を整理します。
破損snapshotがある場合は自動整理を中止し、有効な鍵を推測で削除しません。
アプリのデータ消去・アンインストールで検証データを撤去できます。復旧機能はありません。

実装を撤去するときは、このディレクトリと専用仕様を削除します。結果・制約の製品仕様への引継ぎを先に確認してください。
Gradle wrapperはGradleプロジェクトのApache-2.0ライセンスの標準wrapperです。
