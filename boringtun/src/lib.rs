// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

pub mod crypto;

#[cfg(not(any(target_os = "windows", target_os = "android", target_os = "ios")))]
pub mod device;

pub mod ffi;
pub mod noise;

#[cfg(target_os = "android")]
pub mod jni;
