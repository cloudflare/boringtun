#pragma once

#include <pthread.h>
#include <stdatomic.h>
#include "wireguard_ffi.h"

#define WG_BENCH_MAX_THREADS 256
#define WG_BENCH_MAX_ERRORS 32

struct wg_bench_statistics {
    atomic_uintmax_t tx_packets;
    atomic_uintmax_t tx_drops;
    atomic_uintmax_t tx_bytes;
    atomic_uintmax_t rx_packets;
    atomic_uintmax_t rx_bytes;
    atomic_uintmax_t errors[WG_BENCH_MAX_ERRORS];
};

struct wg_bench_client {
    struct wireguard_tunnel *tunnel;
    struct x25519_key secret;
    const char *pubkey;

    struct wg_bench_client* peer;

    // The packet send and receive worker pool.
    int         worker_handshake;
    atomic_bool worker_shutdown;
    int         worker_count;
    pthread_t   background;
    pthread_t   workers[WG_BENCH_MAX_THREADS];

    // Statistics.
    struct wg_bench_statistics stats;
};

struct wg_bench_client* wg_bench_create();
void wg_bench_connect(struct wg_bench_client* client, struct wg_bench_client* peer);
void wg_bench_start_handshake(struct wg_bench_client* client);
void wg_bench_start_send(struct wg_bench_client* client);
void wg_bench_start_worker(struct wg_bench_client* client);
void wg_bench_fetch_stats(const struct wg_bench_client* client, struct wg_bench_statistics* stats);
void wg_bench_close(struct wg_bench_client* client);
