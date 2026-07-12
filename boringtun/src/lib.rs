// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone <https://github.com/cloudflare/boringtun.git></code>
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "device", docsrs))]
#[cfg_attr(docsrs, doc(cfg(feature = "device")))]
pub mod device;

#[cfg(any(feature = "ffi-bindings", docsrs))]
#[cfg_attr(docsrs, doc(cfg(feature = "ffi-bindings")))]
pub mod ffi;

#[cfg(any(feature = "jni-bindings", docsrs))]
#[cfg_attr(docsrs, doc(cfg(feature = "jni-bindings")))]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
