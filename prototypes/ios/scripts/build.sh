#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/module-cache
build_mode="${1:-build}"
rust_target="aarch64-apple-ios-sim"
if [[ "$(uname -m)" == x86_64 ]]; then rust_target="x86_64-apple-ios"; fi
case "$build_mode" in
  test)
    cargo test --locked --manifest-path rust/Cargo.toml
    xcrun swiftc -swift-version 6 -module-cache-path build/module-cache \
      Sources/OperationGate.swift Tests/main.swift -o build/operation-gate-test
    build/operation-gate-test
    ;;
  check|build)
    sdk_path=$(xcrun --sdk iphonesimulator --show-sdk-path)
    simulator_arch=$(uname -m)
    compiler_args=(-swift-version 6 -parse-as-library -sdk "$sdk_path"
      -target "${simulator_arch}-apple-ios18.0-simulator"
      -module-cache-path build/module-cache)
    if [[ "$build_mode" == check ]]; then
      cargo fmt --manifest-path rust/Cargo.toml -- --check
      cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
      plutil -lint Info.plist
      plutil -lint Simulator.entitlements
      xcrun --sdk iphonesimulator swiftc "${compiler_args[@]}" -import-objc-header Bridge/VaultRust.h -typecheck Sources/*.swift
      device_sdk_path=$(xcrun --sdk iphoneos --show-sdk-path)
      xcrun --sdk iphoneos swiftc -swift-version 6 -parse-as-library -sdk "$device_sdk_path" \
        -target arm64-apple-ios18.0 -module-cache-path build/module-cache \
        -import-objc-header Bridge/VaultRust.h -typecheck Sources/*.swift
    else
      cargo build --locked --release --manifest-path rust/Cargo.toml --target "$rust_target"
      mkdir -p build/VaultSimulator.app
      cp Info.plist build/VaultSimulator.app/Info.plist
      xcrun --sdk iphonesimulator swiftc "${compiler_args[@]}" -import-objc-header Bridge/VaultRust.h Sources/*.swift \
        "rust/target/$rust_target/release/libvault_ios.a" -framework Security -framework SystemConfiguration \
        -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __entitlements -Xlinker Simulator.entitlements \
        -o build/VaultSimulator.app/VaultSimulator
      codesign --force --sign - build/VaultSimulator.app
      echo "Built build/VaultSimulator.app (Simulator only)"
    fi
    ;;
  *) echo 'Usage: bash scripts/build.sh check|test|build' >&2; exit 2 ;;
esac
