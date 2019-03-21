// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// JNI bindings for BoringTun library
use std::os::raw::c_char;
use std::ptr;

use jni::objects::{JByteBuffer, JClass, JString};
use jni::strings::JNIStr;
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

use crypto::x25519::X25519SecretKey;
use std::str::FromStr;

use ffi::new_tunnel;
use ffi::wireguard_read;
use ffi::wireguard_result;
use ffi::wireguard_tick;
use ffi::wireguard_write;
use ffi::x25519_key;
use ffi::x25519_key_to_base64;
use ffi::x25519_key_to_hex;
use ffi::x25519_public_key;
use ffi::x25519_secret_key;

use noise::Tunn;

pub extern "C" fn log_print(_log_string: *const c_char) {
    /*
    XXX:
    Define callback function in app.
    */
}

/// Generates new x25519 secret key and converts into java byte array.
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_x25519_1secret_1key"]
pub extern "C" fn generate_secret_key(env: JNIEnv, _class: JClass) -> jbyteArray {
    match env.byte_array_from_slice(&x25519_secret_key().as_bytes()) {
        Ok(v) => v,
        Err(_) => ptr::null_mut(),
    }
}

/// Computes public x25519 key from secret key and converts into java byte array.
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_x25519_1public_1key"]
pub unsafe extern "C" fn generate_public_key1(
    env: JNIEnv,
    _class: JClass,
    arg_secret_key: jbyteArray,
) -> jbyteArray {
    let mut secret_key = [0; 32];

    if env
        .get_byte_array_region(arg_secret_key, 0, &mut secret_key)
        .is_err()
    {
        return ptr::null_mut();
    }

    let secret_key: X25519SecretKey = X25519SecretKey::from_str(&hex::encode(
        std::mem::transmute::<[i8; 32], [u8; 32]>(secret_key),
    ))
    .unwrap();

    match env.byte_array_from_slice(&x25519_public_key(secret_key).as_bytes()) {
        Ok(v) => v,
        Err(_) => ptr::null_mut(),
    }
}

/// Converts x25519 key to hex string.
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_x25519_1key_1to_1hex"]
pub unsafe extern "C" fn convert_x25519_key_to_hex(
    env: JNIEnv,
    _class: JClass,
    arg_key: jbyteArray,
) -> jstring {
    let mut key = [0; 32];

    if env.get_byte_array_region(arg_key, 0, &mut key).is_err() {
        return ptr::null_mut();
    }

    let x25519_key = x25519_key {
        key: std::mem::transmute::<[i8; 32], [u8; 32]>(key),
    };

    let output = match env.new_string(JNIStr::from_ptr(x25519_key_to_hex(x25519_key)).to_owned()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    output.into_inner()
}

/// Converts x25519 key to base64 string.
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_x25519_1key_1to_1base64"]
pub unsafe extern "C" fn convert_x25519_key_to_base64(
    env: JNIEnv,
    _class: JClass,
    arg_key: jbyteArray,
) -> jstring {
    let mut key = [0; 32];

    if env.get_byte_array_region(arg_key, 0, &mut key).is_err() {
        return ptr::null_mut();
    }

    let x25519_key = x25519_key {
        key: std::mem::transmute::<[i8; 32], [u8; 32]>(key),
    };

    let output = match env.new_string(JNIStr::from_ptr(x25519_key_to_base64(x25519_key)).to_owned())
    {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    output.into_inner()
}

/// Creates new tunnel
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_new_1tunnel"]
pub unsafe extern "C" fn create_new_tunnel(
    env: JNIEnv,
    _class: JClass,
    arg_secret_key: JString,
    arg_public_key: JString,
) -> jlong {
    let secret_key = match env.get_string_utf_chars(arg_secret_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let public_key = match env.get_string_utf_chars(arg_public_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let tunnel = new_tunnel(secret_key, public_key, Some(log_print), 3);

    if tunnel.is_null() {
        return 0;
    }

    tunnel as jlong
}

/// Encrypts raw IP packets into WG formatted packets.
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_wireguard_1write"]
pub unsafe extern "C" fn encrypt_raw_packet(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    src: jbyteArray,
    src_size: jint,
    dst: JByteBuffer,
    dst_size: jint,
    op: JByteBuffer,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let op_ptr: *mut u8 = match env.get_direct_buffer_address(op) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let output: wireguard_result = wireguard_write(
        tunnel as *mut Tunn,
        env.convert_byte_array(src).unwrap().as_mut_ptr(),
        src_size as u32,
        dst_ptr,
        dst_size as u32,
    );
    *op_ptr = output.op as u8;

    output.size as i32
}

/// Decrypts WG formatted packets into raw IP packets.
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_wireguard_1read"]
pub unsafe extern "C" fn decrypt_to_raw_packet(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    src: jbyteArray,
    src_size: jint,
    dst: JByteBuffer,
    dst_size: jint,
    op: JByteBuffer,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let op_ptr: *mut u8 = match env.get_direct_buffer_address(op) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let output: wireguard_result = wireguard_read(
        tunnel as *mut Tunn,
        env.convert_byte_array(src).unwrap().as_mut_ptr(),
        src_size as u32,
        dst_ptr,
        dst_size as u32,
    );

    *op_ptr = output.op as u8;

    output.size as i32
}

/// Periodic function that writes WG formatted packets into destination buffer
#[no_mangle]
#[export_name = "Java_com_cloudflare_app_wireguard_WireGuardJNI_00024Companion_wireguard_1tick"]
pub unsafe extern "C" fn run_periodic_task(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    dst: JByteBuffer,
    dst_size: jint,
    op: JByteBuffer,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let op_ptr: *mut u8 = match env.get_direct_buffer_address(op) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let output: wireguard_result = wireguard_tick(tunnel as *mut Tunn, dst_ptr, dst_size as u32);

    *op_ptr = output.op as u8;

    output.size as i32
}
