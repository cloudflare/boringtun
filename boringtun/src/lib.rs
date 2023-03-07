#![allow(clippy::all)]
#![allow(semicolon_in_expressions_from_macros)]
// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(all(unix, feature = "device"))]
pub mod device;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub mod noise;

pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
