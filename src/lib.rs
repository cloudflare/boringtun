// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

// YAT: silence warnings emitted by the vendored boringtun 0.7.1 tree so the
// vendor directory stays close to upstream. Each allow maps to a known class
// of diagnostics that would otherwise require non-trivial upstream API
// migrations or feature-gated code paths:
//   * `deprecated` — `ring::constant_time::verify_slices_are_equal` and
//     `base64::decode` still work but have newer replacements; migrating them
//     is tracked separately.
//   * `mismatched_lifetime_syntaxes` — elided lifetimes on `Iter`,
//     `LockReadGuard`, `Packet` return types are stylistic hints only.
//   * `unused_variables` / `dead_code` — parameters and helpers such as
//     `fwmark`, `set_persistent_keepalive`, `KeyBytes` are used only under
//     certain feature combinations (see YAT_PATCHES.md).
// Any new local change to this vendor tree must be recorded in YAT_PATCHES.md.
#![allow(deprecated)]
#![allow(mismatched_lifetime_syntaxes)]
#![allow(unused_variables)]
#![allow(dead_code)]

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
  pub use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret};
}
