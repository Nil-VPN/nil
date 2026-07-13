//! Build-time guard against JNI symbol drift.
//!
//! Kotlin's `external fun nativeStart(...)` on `object NilNative` in package `com.nilvpn` binds at
//! runtime, purely by name-mangling, to the `#[no_mangle] pub extern "system" fn
//! Java_com_nilvpn_NilNative_nativeStart` symbol in this crate. Nothing checks that correspondence
//! at compile time — a rename on either side surfaces only as a runtime `UnsatisfiedLinkError` on a
//! real device, the most expensive place to find it.
//!
//! This build script reads the canonical `android/NilNative.kt` and `src/lib.rs` and fails the build
//! if any Kotlin `external fun` lacks its matching `Java_com_nilvpn_NilNative_<name>` export. It runs
//! on EVERY build of this crate — including the desktop `cargo build --workspace` (the crate body is
//! `#![cfg(target_os = "android")]`-empty there, but build scripts run regardless of target) — so
//! plain CI catches the drift without an Android toolchain or a device.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let kt_path = manifest.join("android/NilNative.kt");
    let rs_path = manifest.join("src/lib.rs");
    println!("cargo:rerun-if-changed={}", kt_path.display());
    println!("cargo:rerun-if-changed={}", rs_path.display());

    let kt = std::fs::read_to_string(&kt_path).unwrap_or_else(|e| {
        panic!(
            "nil-android symbol guard: cannot read {}: {e}",
            kt_path.display()
        )
    });
    let rs = std::fs::read_to_string(&rs_path).unwrap_or_else(|e| {
        panic!(
            "nil-android symbol guard: cannot read {}: {e}",
            rs_path.display()
        )
    });

    // The JNI symbol prefix is derived from the Kotlin package + object name. If either changes, the
    // mangled prefix changes too, so assert them explicitly rather than hard-trusting the constant.
    assert!(
        kt.contains("package com.nilvpn"),
        "nil-android symbol guard: NilNative.kt is not in package `com.nilvpn`; the \
         Java_com_nilvpn_NilNative_* symbols in src/lib.rs would no longer match — update both."
    );
    assert!(
        kt.contains("object NilNative"),
        "nil-android symbol guard: NilNative.kt no longer declares `object NilNative`; the \
         Java_com_nilvpn_NilNative_* symbols in src/lib.rs would no longer match — update both."
    );
    const PREFIX: &str = "Java_com_nilvpn_NilNative_";

    // Every Kotlin `external fun <name>(` must have a matching Rust export. (Rust may export more,
    // e.g. JNI_OnLoad, which has no Kotlin declaration — so we only check the Kotlin→Rust direction,
    // the one that fails at runtime with UnsatisfiedLinkError.)
    let mut missing: Vec<String> = Vec::new();
    for name in kt
        .lines()
        .filter_map(|l| l.trim().strip_prefix("external fun "))
        .filter_map(|rest| rest.split('(').next())
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
    {
        let symbol = format!("{PREFIX}{name}");
        if !rs.contains(&symbol) {
            missing.push(symbol);
        }
    }

    if !missing.is_empty() {
        panic!(
            "nil-android JNI symbol guard FAILED: NilNative.kt declares `external fun`s with no \
             matching export in src/lib.rs (would be an UnsatisfiedLinkError at runtime): {missing:?}. \
             Add `#[no_mangle] pub extern \"system\" fn <symbol>` for each, or rename to match."
        );
    }
}
