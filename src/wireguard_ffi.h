#pragma once

#include <stdint.h>

struct wireguard_tunnel; // This corresponds to the Rust type

enum
{
    MAX_WIREGUARD_PACKET_SIZE = 65536 + 64,
};

enum result_type
{
    WIREGUARD_DONE = 0,
    WRITE_TO_NETWORK = 1,
    WIREGUARD_ERROR = 2,
    WRITE_TO_TUNNEL_IPV4 = 4,
    WRITE_TO_TUNNEL_IPV6 = 6,
};

enum log_level
{
    NONE = 0,
    INFO = 1,
    DEB = 2,
    ALL = 3,
};

struct wireguard_result
{
    enum result_type op;
    uint32_t size;
};

struct x25519_key
{
    uint8_t key[32];
};

// Generates a fresh x25519 secret key
struct x25519_key x25519_secret_key();
// Computes an x25519 public key from a secret key
struct x25519_key x25519_public_key(struct x25519_key private_key);
// Encodes a public or private x25519 key to base64
const char *x25519_key_to_base64(struct x25519_key key);
// Encodes a public or private x25519 key to hex
const char *x25519_key_to_hex(struct x25519_key key);
// Check if a null terminated string represents a valid x25519 key
// Returns 0 if not
int check_base64_encoded_x25519_key(const char *key);

// Allocate a new tunnel
struct wireguard_tunnel *new_tunnel(const char *static_private,
                                    const char *server_static_public,
                                    void (*log_printer)(const char *),
                                    enum log_level log_level);

struct wireguard_result wireguard_write(struct wireguard_tunnel *tunnel,
                                        const uint8_t *src,
                                        uint32_t src_size,
                                        uint8_t *dst,
                                        uint32_t dst_size);

struct wireguard_result wireguard_read(struct wireguard_tunnel *tunnel,
                                       const uint8_t *src,
                                       uint32_t src_size,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_tick(struct wireguard_tunnel *tunnel,
                                       uint8_t *dst,
                                       uint32_t dst_size);

const uint8_t *benchmark(int32_t name, uint32_t idx);
