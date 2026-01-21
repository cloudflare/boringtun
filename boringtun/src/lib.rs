// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

// Set `no_std` where `std` feature is disabled
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
