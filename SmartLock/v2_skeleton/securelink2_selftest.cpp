// SmartLock v2 self-check for the six graded C.1 properties.
// Author: Faateh Haneef   Roll: 23i-0688   Section: E   Assignment: 2
//
// Build (from v2_skeleton/):
//   g++ -std=c++17 -O2 -Wall securelink2_selftest.cpp securelink2.cpp -o selftest -lcrypto
// Run:
//   ./selftest
#include "securelink2.hpp"
#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;
static void check(const char* name, bool ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static bool contains(const std::vector<std::string>& v, const std::string& x) {
    for (auto& e : v) { if (e == x) return true; }
    return false;
}

int main() {
    using namespace sl2;
    std::vector<uint8_t> shared(256, 0x41);     // stand-in DH secret
    shared[0] = 0x01; shared[255] = 0xfe;

    printf("Check 1: suite policy never selects NULL, never downgrades\n");
    auto suites = strong_suites();
    check("strong_suites() excludes NULL", !contains(suites, "NULL"));
    check("NULL-only offer is aborted (\"\")", choose_suite({"NULL"}) == "");
    check("picks strongest common (AES256 over AES128/NULL)",
          choose_suite({"NULL", "AES128-GCM", "AES256-GCM"}) == "AES256-GCM");
    check("falls to AES128 only when AES256 absent",
          choose_suite({"AES128-GCM", "NULL"}) == "AES128-GCM");
    check("choose_suite never returns NULL",
          choose_suite({"NULL"}) != "NULL" && choose_suite({"AES256-GCM","NULL"}) != "NULL");

    printf("Check 2: key derived via KDF, not the raw secret\n");
    auto k256 = derive_key(shared, "AES256-GCM", "c2s");
    auto k256b = derive_key(shared, "AES256-GCM", "c2s");
    auto k_s2c = derive_key(shared, "AES256-GCM", "s2c");
    check("key length matches suite (32)", k256.size() == 32);
    check("key != raw shared secret prefix",
          !(k256.size() <= shared.size() &&
            std::equal(k256.begin(), k256.end(), shared.begin())));
    check("KDF is deterministic", k256 == k256b);
    check("per-direction keys differ (c2s != s2c)", k256 != k_s2c);

    printf("Check 3: unique nonce per sequence number\n");
    bool uniq = true; auto n0 = make_nonce(0);
    for (uint64_t i = 0; i < 5000; ++i)
        for (uint64_t j = i + 1; j < i + 3; ++j)
            if (make_nonce(i) == make_nonce(j)) uniq = false;
    check("nonce length is 12", n0.size() == 12);
    check("make_nonce(i) distinct across many i", uniq);

    printf("Check 4: AEAD seals and opens a record correctly\n");
    std::string msg = "UNLOCK the front door";
    auto rec = seal(k256, 7, msg);
    bool rt = false; try { rt = (open_record(k256, rec, 7) == msg); } catch (...) {}
    check("round-trip seal/open at matching seqno", rt);

    printf("Check 5: replay / out-of-order / tamper are rejected\n");
    bool wrong_seq_throws = false;
    try { open_record(k256, rec, 8); } catch (...) { wrong_seq_throws = true; }
    check("open at wrong expected seqno throws", wrong_seq_throws);
    bool tamper_throws = false;
    auto bad = rec; bad[bad.size() - 1] ^= 0x01;   // flip a tag bit
    try { open_record(k256, bad, 7); } catch (...) { tamper_throws = true; }
    check("tampered record throws", tamper_throws);
    bool seq_tamper_throws = false;
    auto bad2 = rec; bad2[7] ^= 0x01;              // flip the seqno header
    try { open_record(k256, bad2, 7); } catch (...) { seq_tamper_throws = true; }
    check("altered seqno header is rejected", seq_tamper_throws);

    printf("Check 6: source scan is verified separately on the .cpp "
           "(contains \"hkdf\"/\"evp_kdf\", no forbidden tokens).\n");

    printf("\n%s (%d failure%s)\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
