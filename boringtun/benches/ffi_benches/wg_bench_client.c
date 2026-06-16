#include "wg_bench_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WG_BENCH_MTU 2048

static void wg_worker_sigmask() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
}

struct wg_bench_iphdr {
    uint8_t vlen;
    uint8_t qos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t cksum;
    uint32_t saddr;
    uint32_t daddr;
};

struct wg_bench_udphdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t length;
    uint16_t cksum;
    uint8_t  dgram[];
};

static void wg_bench_input_packet(struct wg_bench_client *client, const void *data, size_t len) {
    uint8_t plaintext[WG_BENCH_MTU];
    struct wireguard_result result;
    result = wireguard_read(client->tunnel, data, len, plaintext, sizeof(plaintext));
    switch (result.op) {
        case WIREGUARD_DONE:
            break;
        
        case WIREGUARD_ERROR:
            if (result.size < WG_BENCH_MAX_ERRORS) {
                atomic_fetch_add(&client->stats.errors[result.size], 1);
            }
            break;

        case WRITE_TO_NETWORK:
            return wg_bench_input_packet(client->peer, plaintext, result.size);

        case WRITE_TO_TUNNEL_IPV4:
        case WRITE_TO_TUNNEL_IPV6:
            atomic_fetch_add(&client->stats.rx_packets, 1);
            atomic_fetch_add(&client->stats.rx_bytes, result.size);
            break;

        default:
            break;
    }
}

static void* wg_bench_worker(void *arg) {
    struct wg_bench_client *client = (struct wg_bench_client *)arg;
    struct wireguard_result result;
    uint8_t ciphertext[WG_BENCH_MTU + 32];
    uint8_t plaintext[WG_BENCH_MTU];

    struct wg_bench_iphdr *ip = (struct wg_bench_iphdr*)plaintext;
    struct wg_bench_udphdr *udp = (struct wg_bench_udphdr*)(ip+1);
    const in_addr_t src = inet_addr("172.16.0.123");
    const in_addr_t dst = inet_addr("172.16.0.1");

    // Generate a sample IPv4 packet header.
    memset(ip, 0, sizeof(struct wg_bench_iphdr));
    ip->vlen = 0x40 + (sizeof(struct wg_bench_iphdr) / 4);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = htonl(src);
    ip->daddr = htonl(dst);
    udp->sport = 0x1234;
    udp->dport = 0x5678;
    udp->cksum = 0;

    wg_worker_sigmask();
    while (!atomic_load(&client->worker_shutdown)) {
        // Pick a random datagram size between 512-1024 and fill with a random byte.
        int dsize = 512 + (rand() % 512);
        int pktlen = sizeof(struct wg_bench_iphdr) + sizeof(struct wg_bench_udphdr) + dsize;
        memset(udp->dgram, rand() & 0xff, dsize);
        udp->length = htons(sizeof(struct wg_bench_udphdr) + dsize);
        udp->cksum = 0;
        ip->tot_len = htons(pktlen);
        ip->cksum = 0;

        // Encrypt the packet.
        result = wireguard_write(client->tunnel, plaintext, pktlen,
                                 ciphertext, sizeof(ciphertext));
        switch (result.op) {
            case WIREGUARD_DONE:
                break;

            case WIREGUARD_ERROR:
                if (result.size < WG_BENCH_MAX_ERRORS) {
                    atomic_fetch_add(&client->stats.errors[result.size], 1);
                }
                fprintf(stderr, "worker encrypt error: %zu\n", result.size);
                break;

            case WRITE_TO_NETWORK:
                atomic_fetch_add(&client->stats.tx_packets, 1);
                atomic_fetch_add(&client->stats.tx_bytes, pktlen);
                wg_bench_input_packet(client->peer, ciphertext, result.size);
                break;

            case WRITE_TO_TUNNEL_IPV4:
            case WRITE_TO_TUNNEL_IPV6:
                // Not expected in this case.
                fprintf(stderr, "worker encrypt tunnel\n");
                break;

            default:
                fprintf(stderr, "worker encrypt unknown: %d\n", result.op);
                break;
        }
    }

    return NULL;
}

static void *wg_bench_background(void* arg) {
    struct wg_bench_client *client = (struct wg_bench_client *)arg;
    uint8_t ciphertext[WG_BENCH_MTU + 32];

    wg_worker_sigmask();
    while (!atomic_load(&client->worker_shutdown)) {
        struct wireguard_result result;
        result = wireguard_tick(client->tunnel, ciphertext, sizeof(ciphertext));

        // Process timeouts and state updates.
        switch (result.op) {
            case WIREGUARD_DONE:
                usleep(100000);
                break;

            case WIREGUARD_ERROR:
                fprintf(stderr, "worker tick error: %zu\n", result.size);
                break;

            case WRITE_TO_NETWORK:
                wg_bench_input_packet(client->peer, ciphertext, result.size);
                break;

            case WRITE_TO_TUNNEL_IPV4:
            case WRITE_TO_TUNNEL_IPV6:
                // not expected
                fprintf(stderr, "worker tick tunnel");
                break;
            
            default:
                fprintf(stderr, "worker tick unknown: %d\n", result.op);
                return NULL;
        }
    }

    return NULL;
}

struct wg_bench_client* wg_bench_create() {
    struct wg_bench_client* client = calloc(sizeof(struct wg_bench_client), 1);
    if (!client) {
        return NULL;
    }
    client->secret = x25519_secret_key();
    client->pubkey = x25519_key_to_base64(x25519_public_key(client->secret));
    return client;
}

void wg_bench_connect(struct wg_bench_client* client, struct wg_bench_client* peer) {
    const char* statickey = x25519_key_to_base64(client->secret);
    client->peer = peer;
    client->tunnel = new_tunnel(statickey, peer->pubkey, NULL, 5, rand() & 0xffffff);
    x25519_key_to_str_free(statickey);

    pthread_create(&client->background, NULL, wg_bench_background, client);
}

void wg_bench_start_handshake(struct wg_bench_client* client) {
    uint8_t ciphertext[WG_BENCH_MTU + 32];
    struct wireguard_result result;
    result = wireguard_force_handshake(client->tunnel, ciphertext, sizeof(ciphertext));

    const struct sockaddr* peer = (const struct sockaddr*)&client->peer;
    socklen_t peerlen = sizeof(client->peer);

    // Process timeouts and state updates.
    switch (result.op) {
        case WIREGUARD_DONE:
            break;

        case WIREGUARD_ERROR:
            fprintf(stderr, "worker handshake error: %zu\n", result.size);
            break;

        case WRITE_TO_NETWORK:
            wg_bench_input_packet(client->peer, ciphertext, result.size);
            break;

        case WRITE_TO_TUNNEL_IPV4:
        case WRITE_TO_TUNNEL_IPV6:
            // not expected
            fprintf(stderr, "worker handshake tunnel");
            break;
        
        default:
            fprintf(stderr, "worker handshake unknown: %d\n", result.op);
            return;
    }
}

void wg_bench_start_worker(struct wg_bench_client* client) {
    if (client->worker_count >= WG_BENCH_MAX_THREADS) {
        return;
    }
    if (pthread_create(&client->workers[client->worker_count], NULL, wg_bench_worker, client) != 0) {
        return;
    }
    client->worker_count++;
}

void wg_bench_fetch_stats(const struct wg_bench_client* client, struct wg_bench_statistics* st) {
    atomic_fetch_add(&st->tx_packets, atomic_load(&client->stats.tx_packets));
    atomic_fetch_add(&st->tx_drops, atomic_load(&client->stats.tx_drops));
    atomic_fetch_add(&st->tx_bytes, atomic_load(&client->stats.tx_bytes));
    atomic_fetch_add(&st->rx_packets, atomic_load(&client->stats.rx_packets));
    atomic_fetch_add(&st->rx_bytes, atomic_load(&client->stats.rx_bytes));
    for (int i = 0; i < WG_BENCH_MAX_ERRORS; i++) {
        atomic_fetch_add(&st->errors[i], atomic_load(&client->stats.errors[i]));
    }
}

void wg_bench_close(struct wg_bench_client* client) {
    // Signal that we are shutting down and terminate workers.
    atomic_store(&client->worker_shutdown, true);
    pthread_join(client->background, NULL);
    for (int i = 0; i < client->worker_count; i++) {
        pthread_cancel(client->workers[i]);
        pthread_join(client->workers[i], NULL);
    }

    x25519_key_to_str_free(client->pubkey);
    tunnel_free(client->tunnel);
}
