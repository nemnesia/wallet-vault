# Chrome 拡張 / Passkey × Rust WASM プロトタイプ

Passkey の PRF 出力から用途別の鍵を導出し、Rust/WASM で検証データを暗号化して
IndexedDB に保存します。拡張ページを開き直し、Passkey で再認証して復号できることを確認します。
検証平文・DEK は WASM 内で扱い、画面には復号・照合の結果だけを返します。

このディレクトリ内のコード・依存・テスト・生成物は、検証後にまとめて削除する予定です。
[実装仕様](../../../vault-docs/docs/prototypes/chrome-extension-implementation.md)と
[検証計画](../../../vault-docs/docs/prototypes/authentication-adapters.md)もプロトタイプ専用です。

## 準備とビルド

必要なものは Node.js / npm、Rust / Cargo、wasm-pack、wasm32-unknown-unknown target、
Chrome Stable と PRF に対応する認証器・provider です。
WASM は同梱し、認証先サーバや Chrome Web Store への登録は不要です。

```sh
cd vault/prototypes/chrome-extension
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --version 0.15.0 --locked
npm ci
npm run build
```

wasm-pack が既にある場合、インストールは不要です。
`npm ci` は lockfile を使います。Rust のビルドも `--locked` で実行します。
`dist/` が、そのまま読み込める拡張ディレクトリです。

実装時に使用した環境：Node.js 26.12.1、npm 11.20.0、Rust/Cargo 1.98.0、
wasm-pack 0.15.0。依存の正確な版は package-lock.json / rust/Cargo.lock を参照してください。

## Chrome で確認する手順

1. `chrome://extensions` を開き、デベロッパーモードを有効にします。
2. 「パッケージ化されていない拡張機能を読み込む」から、このディレクトリの `dist/` を選びます。
3. 拡張アイコンをクリックして検証タブを開き、実行環境・認証器/provider を記録します。
4. 「Passkeyを登録して保存」を押します。登録、Profile用PRF、Signing用PRFの認証を順に進めます。
5. 保存完了後にタブを閉じ、拡張アイコンから開き直します。Profile の一覧が残り、状態が `locked` であることを確認します。
6. 「Profileを復号」を押し、再認証後に `unlocked` と復号成功のログが出ることを確認します。
7. 「一回限りの要求を準備」→「再認証してSigningデータを照合」を押します。新たな認証が要求され、照合に成功することを確認します。
8. 手順7を繰り返し、毎回認証画面が再提示されるかを観測欄へ記録します。

`public/manifest.json` の公開鍵で開発時の拡張 ID を固定しています。
再ビルド時もこの公開鍵を変更しないでください。開発用の公開鍵だけを保存し、対応する秘密鍵は保存していません。

実装が userVerification を required にしても、実際の認証が指紋・顔・PIN のどれかは環境によります。
PRF の非対応は UNSUPPORTED と表示します。別方式に自動で切り替えません。

## 失敗を確認する操作

- **取消**：認証中に「取消」。復号されず、準備済み要求が無効になることを確認します。
- **ロック**：認証中や解除後に「ロック」。遅れて返った認証応答が Session を復活させないことを確認します。
- **改ざん**：locked 状態で「改ざんしたコピーで復号を試す」。認証後に INTEGRITY_FAILED となります。保存済みの暗号文は変更しません。
- **別Passkey**：異なる Passkey を選んで2件登録し、「別Passkeyで復号を試す」。選択中 Profile をもう一方の Credential で解除しようとして、完全性検証に失敗することを確認します。
- **原子的保存**：「保存途中でabortを注入」を有効にして新規登録。STORAGE_FAILED となり、一覧更新後も部分 Profile が増えないことを確認します。確認後はチェックを外します。

登録途中に失敗すると、認証器側だけに Credential が残る場合があります。
必要なら認証器/provider の管理機能から検証用 Credential を削除してください。
本 PoC に保存済み Profile の削除・復旧・Credential 自動削除の機能はありません。

## 検証結果の記録

「非秘密の結果をコピー」で、環境・操作段階・結果分類・手動観測を JSON としてコピーできます。
実機結果は検証計画の CHR-01〜04 / COM-01/02 等の ID ごとに判断してください。
画面の操作成功表示を、実認証器の毎回認証に関する自動 PASS とみなしません。

認証情報・PRF・鍵・平文・Credential ID はログへ記録しません。
provider 名と観測欄は自由入力なので、秘密情報を記入しないでください。

## 自動検証

```sh
npm run check
npm test
npx playwright install chromium
npm run test:browser
```

- `check`：WASM ビルド、TypeScript、Rust format、Native/WASM Clippy。
- `test`：標準暗号ベクトル、誤キー・改ざん・用途分離、要求消費・期限、取消競合、IndexedDB の原子的保存。
- `test:browser`：実際の MV3 拡張・WASM・IndexedDB を Chromium で実行します。
  WebAuthn 応答だけをテストプロセスで模擬します。模擬認証コードを配布物に同梱しないことも検証します。

2026-10-22 の確認結果：上記チェック、Rust 4件・TypeScript 10件、ブラウザ統合検証は成功。
Chromium for Testing 156.0.8078.4 上で実行しました。
その後ユーザーが Windows / Chrome 155 環境で、保存・再認証復号・失敗経路・
連続2回の認証画面の再提示を手動確認しました。認証器/provider名は未記録です。
[手動検証結果と未確認範囲](../../../vault-docs/docs/prototypes/results/2026-10-22-chrome-windows.md)を参照してください。

## 実装と撤去の境界

- `rust/`：AES-256-GCM、HKDF-SHA256、用途別 DEK、検証用バイナリ、Session / 一回限り要求。
- `src/`：WebAuthn、IndexedDB、操作の取消・世代管理、検証画面。
- `public/`：Manifest とタブ起動だけを行う service worker。
- `tests/` / `scripts/`：自動検証。生成物は `pkg/` / `dist/`。

Profile の保存・認証は試験用乱数データだけを対象にします。任意ファイル・ユーザーの秘密値は入力しません。
Profile と Signing は独立 DEK と用途別 PRF 入力を使います。
Session はタブ単位で独立し、worker に鍵・要求を保存しません。別タブへの lock 連動はありません。

実署名、Recovery Key、バックアップ、再ラップ更新・更新競合、Password、Android/iOS は未実装です。
JS/WASM の完全な秘密消去、侵害された同一ページからの隔離、正当な旧データの巻戻し検知は保証しません。
実認証器の保存・同期機能や IndexedDB の不消失も保証しません。

検証結果は製品仕様への結論・制約の引継ぎが済むまで保持します。
その後の撤去時に `prototypes/chrome-extension/`、専用文書、README のプロトタイプ案内を削除します。
ローカル Chrome の拡張を削除するときは、検証用保存データと認証器側 Credential も別々に整理してください。
