// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// Simple implementation of the client side of the WireGuard protocol
#[cfg(target_os = "android")]
use jni;

pub mod crypto;
pub mod ffi;
#[cfg(target_os = "android")]
pub mod jni;
pub mod noise;
