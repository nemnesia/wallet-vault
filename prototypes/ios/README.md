# Vault1 iPhone / Native Rust プロトタイプ

SwiftUI → Swift Adapter → C ABI → Rust で、用途別 DEK のラップ、暗号化保存、再認証後の復号、
一回限りの Signing 検証データ照合を確認します。実署名ではありません。
[実装仕様](../../../vault-docs/docs/prototypes/ios-implementation.md)と
[モバイル基本設計](../../../vault-docs/docs/prototypes/mobile-design.md)が根拠です。
製品実装ではなく、検証後に撤去するプロトタイプです。

## モードと前提

- **SOFTWARE_SIMULATOR**：Simulator 専用のソフトウェア P-256 鍵を Keychain に保存。
  模擬生体認証の後に鍵操作を行います。OS による非エクスポート性・認証強制を証明しません。
- **SECURE_ENCLAVE**：用途別 P-256 秘密鍵の鍵合意操作を
  `privateKeyUsage + biometryCurrentSet`、`WhenPasscodeSetThisDeviceOnly` で保護する実験候補。
  新しい LAContext を毎回作り、鍵操作自体の認証制約を使います。非対応時は自動切替しません。
- **TEST_DOUBLE**：自動統合試験だけで認証結果を注入します。
  Keychain・CryptoKit・保存・C ABI・Rust は実際に通しますが、Face ID の検証ではありません。

backend ごとに保存先と鍵の名前空間を分離します。実機用のソフトウェア鍵経路はありません。
実機の Secure Enclave・毎回認証・生体登録変更による失効は未検証です。
初回画面は SwiftUI。React Native 接続（IOS-06）は未実装です。

## ビルド・起動

Xcode、iOS 18 以上の Simulator ランタイム、Swift 6、Rust、Node.js が必要です。
Node の外部依存はありません。Rust は初回に依存を取得します。

```sh
cd vault/prototypes/ios
rustup target add aarch64-apple-ios-sim  # Apple Silicon
# Intel Mac は x86_64-apple-ios
npm run check
npm test
npm run build
xcrun simctl list devices available
```

check は Rust fmt/Clippy、plist、Simulator・実機条件の Swift 型チェック。
実機条件の型チェックは実機ビルド・インストール・実測の成功ではありません。
ビルド成果物は `build/VaultSimulator.app`。Simulator 専用の Keychain entitlement を
Mach-O に埋め込み、ad-hoc 署名します。`VAULTSIM01` はローカル試験用 prefix で実在チームではありません。
実機の署名・provisioning profile へ流用しないでください。

```sh
xcrun simctl boot <UDID>  # 未起動の場合
xcrun simctl bootstatus <UDID> -b
xcrun simctl install <UDID> build/VaultSimulator.app
xcrun simctl launch <UDID> dev.vault.prototype.ios.simulator
```

GUI は Xcode の Open Developer Tool → Simulator から開いてください。
初回の「Face ID の使用を許可」ダイアログでは、ユーザーが「許可」を選んでから確認を進めます。

## Simulator での手動確認

1. SOFTWARE_SIMULATOR を選び、Simulator の **Features → Face ID → Enrolled** をオンにします。
2. 検証用の表示名で「認証して登録・保存」。Profile 用・Signing 用の各認証に **Matching Face** を送ります。
3. `SAVED_LOCKED` と一覧を確認し、アプリを終了・再起動します。
4. 「再認証して Profile を復号」に新しい Matching Face を送り、`PROFILE_VERIFIED / unlocked` を確認します。
5. 「要求を準備 → 再認証して Signing データを照合」を2回行い、毎回新しい認証操作を確認します。
6. Non-matching Face・取消では成功しないこと、Signing 取消は unlocked を維持し要求を捨てることを確認します。
7. 認証中・unlocked・要求準備中にホームへ移動し、復帰時に locked・要求なしであることを確認します。
8. 保存途中 abort、改ざんコピー、別 Profile の鍵（2件登録後）を試します。既存保存データは変更しません。
9. 検証用 Signing 鍵の削除は確認ダイアログ付きです。削除後の照合は KEY_INVALIDATED、Profile の解除は継続可能です。

Profile 解除と認証操作は60秒、一回限り要求も準備から60秒です。Signing-DEK は Session に保持しません。
端末 passcode への切替は提供しません。認証画面に伴う inactive では中止せず、background で lock します。
結果の共有には backend・OS・状態・分類だけを含めます。DEK・平文・OS 鍵表現は共有しません。

## 自動検証

```sh
npm run test:simulator -- <UDID>
```

専用の保存先と Keychain 名前空間で TEST_DOUBLE 試験を実行し、別プロセスへ再起動して再解除・照合まで確認します。
対話用 Profile は触りません。試験中はアプリの画面を操作しないでください。
非秘密の結果は `build/evidence/ios-integration-{roundtrip,restart}.json` にコピーします。
今回の実行 ID を照合して古いレポートの誤読を防ぎます。終了時は通常のアプリを locked で開き直します。
この成功で IOS-01〜06 全体を合格にしません。

実際の LocalAuthentication に模擬 Face ID を送る別試験もあります。
同じ Simulator の試験は同時実行せず、順に実行してください。

```sh
npm run test:biometrics -- <UDID>
```

Face ID の初回利用許可は Simulator のダイアログで「許可」を選んでください。
未登録拒否・登録時2回・Profile解除・Signing連続2回・Non-matching Face・context取消を確認します。
模擬入力には private な Simulator 通知を使います。通知名の参考は
[AutoMobile の実装検討](https://github.com/kaeawc/auto-mobile/issues/2497)です。
この方式は検証スクリプトだけで使用し、アプリや実機には組み込みません。
終了時に Simulator の登録状態を元へ戻します。結果は `build/evidence/ios-biometric-*.json`。
物理センサーの Face ID と鍵保護の確認ではありません。

## 所有・保存・撤去

Rust は独立 DEK・レコード AES-GCM・Session・一回限り要求を所有し、Swift は鍵操作と保存を調整します。
OS 鍵との ECDH 共有秘密から HKDF-SHA256 で一時 KEK を導出し、DEK を AES-GCM で保護します。
Secure Enclave の鍵そのものを HKDF に入力するために抽出しません。
DEK は内部 C ABI の32バイト buffer を一時的に通り、使用後にクリアします。
Swift/CryptoKit/FFI 内部コピーの完全消去は保証しません。

保存先は Application Support/VaultIOS-v1/backend。snapshot は backup 対象外・ファイル保護付きで、
一時ファイルから rename して新規公開し、既存 Profile を上書きしません。
Keychain と保存の共通 transaction はなく、プロセス終了で未参照鍵が残る場合があります。
破損保存データから既存鍵を推測して自動削除しません。
Signing 鍵参照の削除は Keychain の項目削除です。実機の生体変更による失効の代用にはしません。
OS による実際の生体登録変更、lockout、ロック設定変更は手動・実機の別検証です。
Recovery・製品 API・RN・実署名・他 PoC との保存互換性は含めません。

撤去時はこのディレクトリを削除できます。アプリをアンインストールしても Keychain 項目は残り得ます。
検証結果・制約を製品仕様へ引き継ぐまでは、結果資料を保持してください。
