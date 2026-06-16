#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h> 
#include <pthread.h>
#include <unistd.h>

#include "wireguard_ffi.h"
#include "wg_bench_client.h"

// Exiting because of a signal.
static int caught_sigint = 0;

static void wg_printf(const char* format, ...) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        // If on a terminal - clear the line and reset before printing.
        char fmtbuf[ws.ws_col + strlen(format) + 3];
        fmtbuf[0] = '\r';
        memset(&fmtbuf[1], ' ', ws.ws_col);
        fmtbuf[ws.ws_col+1] = '\r';
        strcpy(&fmtbuf[2+ws.ws_col], format);

        va_list args;
        va_start(args, format);
        vprintf(fmtbuf, args);
        va_end(args);
    } else {
        // Otherwise, just print it.
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

static void wg_print_msg(const char* msg) {
    wg_printf("%s", msg);
}

static void handle_signal(int sig) {
    switch (sig) {
        case SIGINT:
            wg_printf("benchmark interrupted\n");
            caught_sigint = 1;
            break;

        case SIGTERM:
            wg_printf("benchmark terminated\n");
            caught_sigint = 1;
            break;
        
        case SIGHUP:
            // Do nothing.
            break;
    }
}

static long timespec_cmp(const struct timespec *a, const struct timespec* b) {
    long i = (a->tv_sec - b->tv_sec);
    return i ? i : (a->tv_nsec - b->tv_nsec);
}

static double timespec_elapsed(const struct timespec *a, const struct timespec* b) {
    double result = (a->tv_sec - b->tv_sec) * 1000000000.0;
    return (double)(result + a->tv_nsec - b->tv_nsec) / 1000000000.0;
}

static const char* print_bytes(uintmax_t value, char* buffer, size_t bufsize) {
    const char* suffix = NULL;
    double vfloat;
    if (value > 1000000000) {
        suffix = "GB";
        vfloat = value / 1000000000.0;
    } else if (value > 1000000) {
        suffix = "MB";
        vfloat = value / 1000000.0;
    } else if (value > 1000.0) {
        suffix = "kB";
        vfloat = value / 1000.0;
    } else {
        suffix = "B";
        vfloat = (double)value;
    }

    int len = snprintf(buffer, bufsize, "%.3F %s", vfloat, suffix);
    return buffer;
}

static void print_stats(const struct wg_bench_statistics* st, double walltime, double cputime) {
    uintmax_t total_errors = 0;
    uintmax_t total_bytes = atomic_load(&st->tx_bytes) + atomic_load(&st->rx_bytes);
    for (int i = 0; i < WG_BENCH_MAX_ERRORS; i++) {
        total_errors += atomic_load(&st->errors[i]);
    }

    char loadbuf[16];
    snprintf(loadbuf, sizeof(loadbuf), "%.1F%%", 100.0 * cputime / walltime);

    // Estimate the total throughput.
    char xfer[32];
    char tpbuf[32];
    uintmax_t throughput = total_bytes / walltime;

    // Prepare the status to write.
    char linebuf[120];
    int len = snprintf(linebuf, sizeof(linebuf),
                       "   tx:%-12lu rx:%-12lu drops:%-8lu err:%-8lu load:%8s  %s transferred (%s/s)",
                       atomic_load(&st->tx_packets), atomic_load(&st->rx_packets), atomic_load(&st->tx_drops),
                       total_errors, loadbuf, print_bytes(total_bytes, xfer, sizeof(xfer)),
                       print_bytes(total_bytes / walltime, tpbuf, sizeof(tpbuf)));
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        // If we are on an interactive terminal, refresh the status line
        dprintf(STDOUT_FILENO, "\r%s%*s\r", linebuf, ws.ws_col - len - 1, "");
    } else {
        // Some other file.
        printf("%s\n", linebuf);
    }
}

static void print_errors(const struct wg_bench_statistics* st) {
    // From errors.rs
    const char* names[] = {
        "DestinationBufferTooSmall",
        "IncorrectPacketLength",
        "UnexpectedPacket",
        "WrongPacketType",
        "WrongIndex",
        "WrongKey",
        "InvalidTai64nTimestamp",
        "WrongTai64nTimestamp",
        "InvalidMac",
        "InvalidAeadTag",
        "InvalidCounter",
        "DuplicateCounter",
        "InvalidPacket",
        "NoCurrentSession",
        "LockFailed",
        "ConnectionExpired",
        "UnderLoad",
    };
    const int maxerr = sizeof(names)/sizeof(char*);

    int maxname = 0;
    for (int i = 0; i < maxerr; i++) {
        if (strlen(names[i]) > maxname) {
            maxname = strlen(names[i]);
        }
    }

    wg_printf("\nError Report:\n");
    for (int i = 0; i < maxerr; i++) {
        wg_printf("   %*s: %lu\n", maxname, names[i], atomic_load(&st->errors[i]));
    }
}

static void print_usage(FILE* fp, const char* name) {
    fprintf(fp, "Usage: %s [OPTIONS]\n", name);
    fprintf(fp, "Run FFI benchmarks for the boringtun library.\n");
    fprintf(fp, "\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "\t--time, -t DUR   run benchmark for DUR seconds\n");
    fprintf(fp, "\t--jobs, -j NUM   create NUM parallel threads\n");
    fprintf(fp, "\t--help, -h       display this message and exit\n");
}

int main(int argc, char* argv[]) {
    const char* shortopts = "t:j:h";
    const struct option longopts[] = {
        {"time", required_argument, 0, 't'},
        {"jobs", required_argument, 0, 'j'},
        {"help", no_argument,       0, 'h'},
        {NULL, 0, 0, 0}
    };
    unsigned int num_workers = 1;
    unsigned int duration = 10;

    // Parse options
    while (true) {
        int index;
        int opt = getopt_long(argc, argv, shortopts, longopts, &index);
        if (opt < 0) {
            break;
        }

        char* endp;
        switch (opt) {
            case 't':
                duration = strtoul(optarg, &endp, 10);
                if (*endp != '\0' || (duration == 0)) {
                    fprintf(stderr, "Invalid duration: %s\n", optarg);
                    return 1;
                }
                break;

            case 'j':
                num_workers = strtoul(optarg, &endp, 10);
                if (*endp != '\0' || (num_workers == 0)) {
                    fprintf(stderr, "Invalid thread count: %s\n", optarg);
                    return 1;
                }
                break;

            case 'h':
                print_usage(stdout, argv[0]);
                return 0;
            
            default:
                break;
        }
    }

    srand(time(0));
    set_logging_function(wg_print_msg);

    // The main thread should handle signals.
    struct sigaction action = {
        .sa_handler = handle_signal,
    };
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    // Create two benchmark clients.
    struct wg_bench_client* a = wg_bench_create();
    struct wg_bench_client* b = wg_bench_create();

    // Connect the two clients.
    wg_bench_connect(a, b);
    wg_bench_connect(b, a);

    struct timespec start;
    struct timespec cpustart;
    struct timespec end;
    struct timespec renegotiate;
    clock_gettime(CLOCK_MONOTONIC, &start);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpustart);
    end.tv_sec = start.tv_sec + duration;
    end.tv_nsec = start.tv_nsec;
    renegotiate.tv_sec = start.tv_sec + 1;
    renegotiate.tv_nsec = start.tv_nsec;

    // Launch workers.
    wg_bench_start_handshake(a);
    for (int i = 0; i < num_workers; i++) {
        wg_bench_start_worker(a);
        wg_bench_start_worker(b);
    }

    struct timespec now;
    struct timespec cpu;
    struct wg_bench_statistics stats;
    while (!caught_sigint) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);

        // Fetch and render the statistics.
        memset(&stats, 0, sizeof(stats));
        wg_bench_fetch_stats(a, &stats);
        wg_bench_fetch_stats(b, &stats);
        print_stats(&stats, timespec_elapsed(&now, &start), timespec_elapsed(&cpu, &cpustart));

        // Check for the end condition.
        if (timespec_cmp(&end, &now) < 0) {
            break;
        }
        if (timespec_cmp(&renegotiate, &now) < 0) {
            renegotiate.tv_sec++;
            wg_bench_start_handshake(a);
        }

        // Sleep for more data.
        usleep(100000);
    }

    memset(&stats, 0, sizeof(stats));
    clock_gettime(CLOCK_MONOTONIC, &now);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
    wg_bench_fetch_stats(a, &stats);
    wg_bench_fetch_stats(b, &stats);
    print_errors(&stats);
    print_stats(&stats, timespec_elapsed(&now, &start), timespec_elapsed(&cpu, &cpustart));
    printf("\n");

    wg_bench_close(a);
    wg_bench_close(b);
}
