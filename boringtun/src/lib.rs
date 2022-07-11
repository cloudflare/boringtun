// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(not(any(target_os = "windows", target_os = "android", target_os = "ios")))]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
pub mod noise;

#[cfg(feature = "jni-bindings")]
pub mod jni;

pub(crate) mod serialization;
