// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// Simple implementation of the client side of the WireGuard protocol
#[cfg(target_os = "android")]
use jni;

#[cfg(target_os = "android")]
pub mod cfjni;
pub mod crypto;
pub mod ffi;
pub mod noise;
