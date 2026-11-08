# Rust Vault v1

Wallet の業務モデルから独立した暗号・鍵管理ライブラリです。
[詳細仕様](../../vault-docs/docs/specifications/rust-vault.md)に従い、用途別の独立 DEK、
Password / PRF / Recovery、更新候補、鍵コンテキストを扱います。
`rust-vault` 0.1.0 は非公開 crate（`publish = false`）です。

## 実装範囲

- Create / AddPurpose / RemovePurpose / Unlock / Decrypt / ReplaceData / Rewrap / RotateDek / Recover / ReissueRecovery / RecoverSelected。
- version 1 の snapshot / data / wrap、AES-256-GCM、HKDF-SHA256、Argon2id v19（64 MiB、t=3、p=4）。
- 取消、所有環境別ハンドル、操作限定鍵、保存確認後の失効、プロセス共有の資源予算・件数上限。
- [C ABI](include/rust_vault.h)と WASM `WasmVault`。WASM は OS 専用要求を公開しません。
- Android / iOS Adapter 向けの Native 段階要求・応答。新しい wrap の準備要求は新規 OS 鍵生成を要求します。

**未実装・未検証の境界：** 製品用 Kotlin / Swift OS Adapter と WebAuthn Adapter、SDK / Wallet 統合、
保存 I/O、認可、UI、配布は含みません。実認証器、Keystore / Secure Enclave、実機の認証強制・
生体登録変更失効・鍵回収、Chrome 拡張での動作は未検証です。
Native 段階要求の test double の成功は、ハードウェア保護や実機対応の証明ではありません。
Linux / WASM では OS 経路を Unsupported とし、OS 専用の秘密 payload を返しません。

## 利用

Rust 1.99 以降と Cargo を使います。依存追加は呼出し側の manifest へ次のように指定します。

```toml
[dependencies]
rust-vault = { path = "/path/to/vault/rust" }
```

`Vault::new(memory_budget_bytes)` には正の予算を明示します。既定値はありません。
`begin(&Request)` → `Step::value()` で Completed / Pending を確認し、Pending の Adapter 要求へ
対応する `AdapterResponse` を `resume(operation_id, request_id, &response)` に渡します。
正規の待機 ID と一致しない応答は拒否し、一致 ID の不正応答は操作を失敗させます。

`Step::value()` は借用です。Step を drop すると結果とその予算予約が解放されます。
必要なコピーは呼出し側の責任で管理・消去してください。`Secret` と秘密を含む要求・結果の Debug は内容を出しません。
コンテキストは `release_context`、候補は `discard_candidate` / `confirm_saved` で別途終了します。
`destroy` は所有環境の状態を失効させますが、返却済み Step の解放を代替しません。

候補は保存成功を意味しません。呼出し側が競合を確認して原子的保存・読戻しを行い、
候補の new_hash を照合してから `confirm_saved` を呼びます。
操作認可、対象選択、完全な期待用途集合、期限、OS 鍵の回収は上位の責任です。

### Native C ABI

```sh
cargo build --locked
```

`target/debug/librust_vault.a`、`librust_vault.so` が生成されます（OS により拡張子は異なります）。
ヘッダーは `include/rust_vault.h` です。C 入力は呼出し中のみ借用し、継続に必要な値は Rust がコピーします。
返却された `VaultStep*` は `vault_free_step` で一度だけ解放し、下位の Bytes を個別解放しません。
NULL と正の長さ・件数は拒否します。非 NULL の不正ポインタ、解放済み領域、二重 free は呼出し契約違反です。
C の panic unwind は境界で捕捉します。OOM abort やプロセス終了の復旧は保証しません。

汎用 Decrypt と秘密を含む Adapter 要求は信頼された Native 内部専用です。
React Native 等へ汎用転送するブリッジは提供しません。

### WASM

`wasm32-unknown-unknown` target、wasm-pack、Node.js が必要です。

```sh
rustup target add wasm32-unknown-unknown
wasm-pack build --target nodejs --dev --out-dir pkg --no-pack -- --locked
node tests/wasm.cjs
```

`pkg/rust_vault.js` と対応する WASM・型定義が生成されます。
ブラウザ用の生成には `--target web` を使います。ブラウザでの実行試験は別途必要です。

`new WasmVault(memory_budget_bytes)` の引数は bigint、各操作メソッドの結果は Promise です。
入力要求は `{ tag, payload }`、Adapter 応答は `{ kind, status, payload }` を使い、
payload のフィールド名は仕様の snake_case に合わせます。
配列は JS Array、バイト列は Uint8Array、すべての uint64（ハンドル・世代を含む）は bigint です。
Number の uint64 と通常 Array のバイト列を拒否します。エラーは仕様の数値で reject します。
出力は `{ tag: 1, payload: { request_tag, payload } }` または
`{ tag: 2, payload: { operation_id, requests } }` です。
実行可能な最小フローは [WASM 試験](tests/wasm.cjs)を参照してください。

JS 出力はコピーされ、Rust 結果の予約は変換終了で解放します。
JS のコピーは呼出し側が管理します。JS / GC の全コピー消去や Native 相当の隔離は保証しません。
Promise メソッドの暗号処理は現状、呼出し先 WASM のスレッドで実行します。
Worker 配置・WebAuthn・ページ終了時の destroy は統合側で行います。

## 資源管理と実装上の制約

Native は全所有環境と未解放結果が同じ予算を共有し、異なる予算指定を拒否します。
WASM はインスタンス単位です。暗号処理・KDF は各1枠、コンテキスト128、操作32、候補32です。
OS・JS・呼出し側コピーを含む RSS 全体の hard limit ではありません。

追加確保前に保守的上界を予約します。現在の実装は、所有入力容量の64倍＋8 MiBを
操作の replay・応答・中間バッファ用に予約し、Password を実処理する操作にはさらに72 MiBを予約します。
後者は64 MiBの明示的 Argon2 workspaceと補助領域の上界です。暗号バックエンドはその workspace を借用します。
各コンテキスト4 KiB、候補の管理情報32 KiB、結果は容量に固定 overhead を足して別途予約し、
所有終了時に予約を解放します。このため形式上限に達する前でも ResourceLimit になり得ます。

継続処理は操作ローカルの乱数 tape・受理済み応答から再評価します。
OS の鍵生成・暗号化を含む受理済み Adapter 処理を再発行せず、Password KDF 結果は操作内だけキャッシュします。
多用途・多経路では共通暗号の再評価コストが増えます。性能適合・推奨予算は未実測です。
これらの定数は内部の保守的予約量であり、製品の既定予算や安全な導入値ではありません。

## 検証

以下はすべて `vault/rust/` で実行します。

```sh
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked -- --test-threads=1
cargo check --locked --target wasm32-unknown-unknown
cargo clippy --locked --target wasm32-unknown-unknown -- -D warnings
cargo check --locked --target aarch64-linux-android
```

Android は Rust のクロス型検査であり、JNI 接続・APK・実機の検証ではありません。
iOS は macOS / Xcode と対応 Rust target で別途ビルド・実機試験が必要です。

Linux の C header / runtime 試験（C compiler が必要）：

```sh
cargo build --locked
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Iinclude tests/c_runtime.c target/debug/librust_vault.a -ldl -lpthread -lm -o target/c_runtime
target/c_runtime
```

Sanitizer は C harness と runtime の境界を検査します。Rust 本体全域を sanitizer で計装した検証ではありません。
LeakSanitizer は ptrace 制約下で実行できないことがあるため、制約のない環境で実行してください。

宣言と公開ベクトルの再生成：

```sh
python3 tools/generate_abi.py
python3 tools/generate_vectors.py
```

ABI 生成には Python・rustfmt、ベクトル生成には Python cryptography の Argon2id 対応版が必要です。
通常の `cargo test` はチェックイン済み fixture を使い、Python は不要です。
[公開テスト値の出典・制約](tests/README.md)を確認してください。
