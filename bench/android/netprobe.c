/* Small HTTP/IPv4 test client for adb shell. Shell traffic traverses the VPN;
 * traffic from com.rawg.vpn itself deliberately does not. No external libraries.
 * Measures confirmed body bytes with CLOCK_MONOTONIC, not nc/EOF timing.
 * Build: NDK aarch64-linux-android26-clang -O2 -Wall -Wextra netprobe.c -o netprobe
 * Usage: netprobe down|up HOST PORT PATH BYTES
 *         netprobe get HOST PORT PATH 0  (small diagnostic response, e.g. /ip)
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

static double mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void die(const char *s) { fprintf(stderr, "netprobe: %s (errno=%d)\n", s, errno); exit(1); }
static int line(int fd, char *out, size_t n) {
    size_t k = 0;
    while (k + 1 < n) {
        ssize_t r = recv(fd, out + k, 1, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        if (out[k++] == '\n') { out[k] = 0; return (int)k; }
    }
    return -1;
}
static void send_all(int fd, const void *b, size_t n) {
    const char *p = b;
    while (n) {
        ssize_t r = send(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) die("send timeout/failure");
        n -= (size_t)r; p += r;
    }
}
static uint64_t recv_exact(int fd, uint64_t n, int show) {
    char b[65536];
    uint64_t got = 0;
    while (got < n) {
        size_t want = n - got < sizeof(b) ? (size_t)(n - got) : sizeof(b);
        ssize_t r = recv(fd, b, want, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) die("short response body or receive timeout");
        if (show) fwrite(b, 1, (size_t)r, stderr);
        got += (uint64_t)r;
    }
    return got;
}
int main(int argc, char **argv) {
    if (argc != 6) die("usage: down|up|get HOST PORT PATH BYTES");
    int up = !strcmp(argv[1], "up"), show = !strcmp(argv[1], "get");
    if (!up && !show && strcmp(argv[1], "down")) die("invalid mode");
    char *end;
    errno = 0;
    uint64_t n = strtoull(argv[5], &end, 10);
    if (errno || *end || n > 1000000000ULL || ((!n || argv[5][0]=='-') && !show)) die("invalid byte count (1..1e9)");
    if (strlen(argv[2]) > 253 || strspn(argv[2], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != strlen(argv[2])) die("invalid host");
    if (argv[4][0] != '/' || strlen(argv[4]) > 2048 || strpbrk(argv[4], "\r\n ")) die("invalid path");
    signal(SIGPIPE, SIG_IGN);
    alarm(180); // Absolute cap as well as per-operation socket timeouts.
    double start = mono();
    struct addrinfo hint = {0}, *res = NULL;
    hint.ai_family = AF_INET; hint.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(argv[2], argv[3], &hint, &res)) die("DNS resolution");
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {15, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (!connect(fd, a->ai_addr, a->ai_addrlen)) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) die("connect");
    double connected = mono();
    char header[4096];
    int len = snprintf(header, sizeof(header),
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: rawg-test/1\r\nConnection: close\r\nAccept-Encoding: identity\r\nContent-Length: %llu\r\n\r\n",
        up ? "POST" : "GET", argv[4], argv[2], (unsigned long long)(up ? n : 0));
    if (len < 0 || (size_t)len >= sizeof(header)) die("header too big");
    send_all(fd, header, (size_t)len);
    if (up) {
        char payload[65536];
        // Deterministic nonzero data, not a compressible sparse upload.
        uint32_t x = 0x12345678;
        for (size_t i = 0; i < sizeof(payload); i++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5; payload[i] = (char)x;
        }
        uint64_t left = n;
        while (left) {
            size_t part = left < sizeof(payload) ? (size_t)left : sizeof(payload);
            send_all(fd, payload, part); left -= part;
        }
    }
    char b[8192];
    if (line(fd, b, sizeof(b)) < 0) die("missing HTTP status");
    int status = 0;
    if (sscanf(b, "HTTP/%*s %d", &status) != 1) die("bad HTTP status");
    if (status != 200) { fprintf(stderr, "HTTP status=%d\n", status); die("HTTP not 200, no speed result"); }
    int chunked = 0;
    int64_t body_len = -1;
    size_t header_size = strlen(b);
    while (1) {
        int r = line(fd, b, sizeof(b));
        if (r < 0 || (header_size += (size_t)r) > 32768) die("invalid HTTP headers");
        if (!strcmp(b, "\r\n") || !strcmp(b, "\n")) break;
        if (!strncasecmp(b, "Content-Length:", 15)) {
            body_len = strtoll(b + 15, &end, 10);
            if (end == b + 15 || (*end != '\r' && *end != '\n' && *end != '\0')) die("invalid Content-Length");
            if (body_len < 0 || body_len > 1000000000LL) die("invalid Content-Length");
        }
        if (!strncasecmp(b, "Transfer-Encoding:", 18)) {
            if (!strstr(b + 18, "chunked")) die("unsupported Transfer-Encoding");
            chunked = 1;
        }
    }
    double body_start = mono();
    uint64_t received = 0, max_body = up || show ? 65536 : n;
    if (chunked) {
        while (1) {
            if (line(fd, b, sizeof(b)) < 0) die("missing chunk size");
            errno = 0;
            unsigned long long chunk = strtoull(b, &end, 16);
            if (errno || end == b || (*end != '\r' && *end != ';') || chunk > max_body - received) die("invalid chunk length");
            if (!chunk) break;
            received += recv_exact(fd, chunk, show);
            if (line(fd, b, sizeof(b)) != 2 || strcmp(b, "\r\n")) die("bad chunk terminator");
        }
    } else if (body_len >= 0) {
        if ((uint64_t)body_len > max_body) die("unexpected body length");
        received = recv_exact(fd, (uint64_t)body_len, show);
    } else {
        while (1) {
            ssize_t r = recv(fd, b, sizeof(b), 0);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) die("receive timeout, no speed result");
            if (!r) break;
            if ((uint64_t)r > max_body - received) die("response exceeded budget");
            if (show) fwrite(b, 1, (size_t)r, stderr);
            received += (uint64_t)r;
        }
    }
    double finished = mono();
    if (!up && !show && received != n) die("incomplete download, no speed result");
    // Обе скорости считаются от установленного соединения (без DNS и connect):
    // up - до заголовков ответа сервера (отправка тела + подтверждение приёма сервером),
    // down - до последнего байта тела (запрос + ожидание первого байта + приём).
    double send_seconds = body_start - connected;
    double xfer_seconds = finished - connected;
    if (xfer_seconds <= 0) xfer_seconds = 1e-9;
    if (send_seconds < 0) send_seconds = 0;
    double elapsed = finished - start;
    if (elapsed <= 0) elapsed = 1e-9;
    struct tcp_info info = {0}; socklen_t ilen = sizeof(info);
    int have_info = !getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &ilen);
    close(fd);
    printf("{\"mode\":\"%s\",\"status\":%d,\"bytes_sent\":%llu,\"body_received\":%llu,\"seconds\":%.6f,\"connect_seconds\":%.6f,\"body_seconds\":%.6f,\"send_seconds\":%.6f,\"mbit_s\":%.3f,\"tcp_rtt_us\":%u,\"tcp_total_retrans\":%u}\n",
        argv[1], status, (unsigned long long)(up ? n : 0), (unsigned long long)received,
        elapsed, connected - start, finished - body_start, send_seconds,
        show ? 0 : (double)(up ? n : received) * 8 / (up ? (send_seconds > 0 ? send_seconds : xfer_seconds) : xfer_seconds) / 1e6,
        have_info ? info.tcpi_rtt : 0, have_info ? info.tcpi_total_retrans : 0);
    return 0;
}
