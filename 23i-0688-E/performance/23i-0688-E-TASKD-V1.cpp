// SmartLock Assignment 2 - Part D: performance study (v1 vs v2).
// Author: Faateh Haneef   Roll: 23i-0688   Section: E   Assignment: 2
//
// Measures the cost of v2's security against the v1 AES256-GCM baseline, on the
// same machine with the same compiler flags. Three families of measurement:
//   * per-record overhead (extra wire bytes vs plaintext) and seal/open latency;
//   * throughput (MB/s) protecting and opening 1 KiB records;
//   * handshake time (TCP connect -> greeting decrypted), against a running lock.
//
// Subcommands:
//   ./taskd micro [records] [runs]        in-process record benchmarks + CSV
//   ./taskd hs-v1 <host> <port> [runs]    time the v1 handshake N times
//   ./taskd hs-v2 <host> <port> [runs]    time the v2 handshake N times
//
// Build (from performance/), all on one line:
//   g++ -std=c++17 -O2 -Wall -I../../SmartLock/smartlock -I../../SmartLock/v2_skeleton 23i-0688-E-TASKD-V1.cpp ../../SmartLock/v2_skeleton/securelink2.cpp -o taskd -lcrypto
#include "slink.hpp"          // v1 records, DH, md5, Msg/Reader/send_msg
#include "securelink2.hpp"    // v2 seal/open/derive_key/choose_suite
#include "dh2048.hpp"         // v2 ephemeral DH
#include "pki.hpp"            // RSA verify
#include <cstdio>
#include <cmath>
#include <chrono>
#include <string>
#include <vector>
#include <random>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using clk = std::chrono::steady_clock;
static double secs(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}
struct Stat { double mean, sd; };
static Stat stats(const std::vector<double>& v) {
    double m = 0; for (double x : v) m += x; m /= v.size();
    double s = 0; for (double x : v) s += (x - m) * (x - m);
    return { m, std::sqrt(s / v.size()) };
}
static std::string join(const std::vector<std::string>& v) {
    std::string s; for (size_t i = 0; i < v.size(); ++i) { if (i) s += ','; s += v[i]; } return s;
}
static int dial(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(fd, (sockaddr*)&a, sizeof a) < 0) { perror("connect"); return -1; }
    return fd;
}

// ---- in-process record benchmarks ----------------------------------------
static void micro(long records, int runs) {
    const size_t SZ = 1024;
    std::string pt(SZ, 'x');
    std::vector<uint8_t> key(32, 0x2b), nonce(12, 0x7);

    // Overhead: measured once (deterministic).
    auto v1rec = slink::record_encrypt("AES256-GCM", key, nonce, pt);
    auto v2rec = sl2::seal(key, 0, pt);
    printf("== per-record overhead (1024 B plaintext) ==\n");
    printf("v1 record bytes = %zu  (overhead %zu: 16-byte GCM tag)\n", v1rec.size(), v1rec.size() - SZ);
    printf("v2 record bytes = %zu  (overhead %zu: 8-byte seqno + 16-byte GCM tag)\n\n",
           v2rec.size(), v2rec.size() - SZ);

    // Latency + throughput over several runs.
    std::vector<double> v1seal, v1open, v2seal, v2open;
    for (int r = 0; r < runs; ++r) {
        auto t0 = clk::now();
        for (long i = 0; i < records; ++i) { auto c = slink::record_encrypt("AES256-GCM", key, nonce, pt); (void)c.size(); }
        auto t1 = clk::now();
        auto c1 = slink::record_encrypt("AES256-GCM", key, nonce, pt);
        for (long i = 0; i < records; ++i) { auto m = slink::record_decrypt("AES256-GCM", key, nonce, c1); (void)m.size(); }
        auto t2 = clk::now();
        for (long i = 0; i < records; ++i) { auto c = sl2::seal(key, (uint64_t)i, pt); (void)c.size(); }
        auto t3 = clk::now();
        auto c2 = sl2::seal(key, 0, pt);
        for (long i = 0; i < records; ++i) { auto m = sl2::open_record(key, c2, 0); (void)m.size(); }
        auto t4 = clk::now();
        v1seal.push_back(secs(t0,t1)); v1open.push_back(secs(t1,t2));
        v2seal.push_back(secs(t2,t3)); v2open.push_back(secs(t3,t4));
    }
    auto mbps = [&](double t){ return (records * (double)SZ) / t / 1e6; };
    auto us   = [&](double t){ return t / records * 1e6; };
    struct Row { const char* name; std::vector<double>& t; };
    Row rows[] = {{"v1 seal",v1seal},{"v1 open",v1open},{"v2 seal",v2seal},{"v2 open",v2open}};
    printf("== latency and throughput (%ld records x %d runs, 1 KiB) ==\n", records, runs);
    printf("%-9s %14s %14s %14s\n", "op", "us/record", "MB/s(mean)", "MB/s(sd)");
    FILE* csv = fopen("taskd_records.csv", "w");
    fprintf(csv, "op,us_per_record,mbps_mean,mbps_sd\n");
    for (auto& row : rows) {
        auto st = stats(row.t);
        std::vector<double> mb; for (double t : row.t) mb.push_back(mbps(t));
        auto ms = stats(mb);
        printf("%-9s %14.3f %14.1f %14.2f\n", row.name, us(st.mean), ms.mean, ms.sd);
        fprintf(csv, "%s,%.3f,%.1f,%.2f\n", row.name, us(st.mean), ms.mean, ms.sd);
    }
    fclose(csv);
    printf("(raw CSV -> taskd_records.csv)\n");
}

// ---- handshake timing: v1 -------------------------------------------------
static double hs_v1(const char* host, int port, std::map<std::string,std::string>& cfg) {
    int s = dial(host, port); if (s < 0) throw std::runtime_error("connect");
    auto t0 = clk::now();
    slink::Reader r(s); slink::Msg m;
    slink::send_msg(s, {{"type","HELLO"},{"suites","AES256-GCM,AES128-GCM,NULL"}});
    r.recv(m); std::string suite = m["suite"];
    r.recv(m);  // CERT
    slink::send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",slink::md5hex(cfg["pin"])}});
    r.recv(m);
    uint64_t p = std::stoull(m["p"]), g = std::stoull(m["g"]), B = std::stoull(m["B"]);
    std::mt19937_64 rng(std::random_device{}());
    uint64_t a = 2 + rng() % (p - 3);
    slink::send_msg(s, {{"type","DHCLIENT"},{"A", std::to_string(slink::modexp(g,a,p))}});
    auto key = slink::session_key(slink::modexp(B,a,p), suite);
    r.recv(m);
    std::string greet = slink::record_decrypt(suite, key, slink::from_hex(m["nonce"]), slink::from_hex(m["ct"]));
    auto t1 = clk::now();
    (void)greet.size(); close(s);
    return secs(t0, t1);
}

// ---- handshake timing: v2 -------------------------------------------------
static double hs_v2(const char* host, int port, std::map<std::string,std::string>& cfg) {
    int s = dial(host, port); if (s < 0) throw std::runtime_error("connect");
    auto t0 = clk::now();
    slink::Reader r(s); slink::Msg m;
    std::string offer = join(sl2::strong_suites());
    slink::send_msg(s, {{"type","HELLO"},{"suites",offer}});
    r.recv(m); std::string suite = m["suite"];
    r.recv(m);  // CERT
    std::string pub_pem = slink::b64dec(m["pubkey"]);
    EVP_PKEY* dev = pki::load_pub(pub_pem);
    pki::verify(dev, m["name"] + pub_pem, slink::from_hex(m["sig"]));
    slink::send_msg(s, {{"type","PAIR"},{"hub",cfg["hub_id"]},{"pinhash",slink::md5hex(cfg["pin"])}});
    r.recv(m);  // DH
    std::string B = m["B"];
    std::string transcript = offer + "|" + suite + "|" + B;
    pki::verify(dev, transcript, slink::from_hex(m["sig"]));
    EVP_PKEY_free(dev);
    std::string apriv, apub; dh2048::keygen(apriv, apub);
    slink::send_msg(s, {{"type","DHCLIENT"},{"A",apub}});
    auto shared = dh2048::shared(B, apriv);
    auto k_s2c = sl2::derive_key(shared, suite, "s2c");
    r.recv(m);  // greeting
    std::string greet = sl2::open_record(k_s2c, slink::from_hex(m["rec"]), 0);
    auto t1 = clk::now();
    (void)greet.size(); close(s);
    return secs(t0, t1);
}

static void run_handshakes(const char* which, const char* host, int port, int runs) {
    auto cfg = slink::read_config("../../SmartLock/smartlock/instance.txt");
    std::vector<double> t;
    for (int i = 0; i < runs; ++i) {
        double e = (std::string(which) == "hs-v1") ? hs_v1(host, port, cfg) : hs_v2(host, port, cfg);
        t.push_back(e * 1000.0);   // ms
        usleep(20000);             // let the lock accept the next connection
    }
    auto st = stats(t);
    printf("== %s handshake, %d runs ==\n", which + 3, runs);
    printf("mean = %.3f ms   sd = %.3f ms\n", st.mean, st.sd);
    FILE* csv = fopen(std::string(std::string("taskd_") + (which+3) + "_handshake.csv").c_str(), "w");
    fprintf(csv, "run_ms\n"); for (double x : t) fprintf(csv, "%.3f\n", x); fclose(csv);
    printf("(raw CSV -> taskd_%s_handshake.csv)\n", which + 3);
}

int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "micro";
    try {
        if (cmd == "micro") {
            long records = argc > 2 ? std::stol(argv[2]) : 10000;
            int runs = argc > 3 ? std::stoi(argv[3]) : 5;
            micro(records, runs);
        } else if (cmd == "hs-v1" || cmd == "hs-v2") {
            const char* host = argc > 2 ? argv[2] : "127.0.0.1";
            int port = argc > 3 ? std::stoi(argv[3]) : 9377;
            int runs = argc > 4 ? std::stoi(argv[4]) : 30;
            run_handshakes(cmd.c_str(), host, port, runs);
        } else {
            fprintf(stderr, "usage: %s micro|hs-v1|hs-v2 ...\n", argv[0]); return 1;
        }
        return 0;
    } catch (const std::exception& ex) { fprintf(stderr, "error: %s\n", ex.what()); return 1; }
}
