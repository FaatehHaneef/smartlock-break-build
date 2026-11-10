// SmartLock v2 record and policy module.
// Author: Faateh Haneef   Roll: 23i-0688   Section: E   Assignment: 2
//
// Security core for v2. Implements the six graded properties:
//   1. suite policy that never selects NULL and never downgrades;
//   2. record key derived from the DH secret with a KDF (HKDF-SHA256, "hkdf"),
//      never the raw secret, with a per-direction context;
//   3. a unique 12-byte nonce per sequence number under a key;
//   4. AEAD (AES-GCM) that seals and opens a record;
//   5. the sequence number is bound into every record (carried in an 8-byte
//      header and authenticated as AAD), and open_record throws when it is not
//      the expected one, rejecting replays and out-of-order records.
//
// Suite is implied by key length (32 -> AES-256-GCM, 16 -> AES-128-GCM).
#include "securelink2.hpp"
#include <cstring>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace sl2 {

// ---- helpers --------------------------------------------------------------
static const EVP_CIPHER* cipher_for(const std::vector<uint8_t>& key) {
    if (key.size() == 32) return EVP_aes_256_gcm();
    if (key.size() == 16) return EVP_aes_128_gcm();
    throw std::runtime_error("unsupported key length");
}
// 8-byte big-endian encoding of the sequence number.
static std::vector<uint8_t> seq_bytes(uint64_t seqno) {
    std::vector<uint8_t> b(8);
    for (int i = 0; i < 8; ++i) b[7 - i] = (uint8_t)((seqno >> (8 * i)) & 0xff);
    return b;
}

// ---- 1. suite policy ------------------------------------------------------
std::vector<std::string> strong_suites() {
    // Strongest first. NULL is never offered or accepted.
    return {"AES256-GCM", "AES128-GCM"};
}

std::string choose_suite(const std::vector<std::string>& hub_offer) {
    // Pick the strongest suite we accept that the hub also offers. Abort with
    // "" rather than fall back to anything weaker; never return "NULL".
    for (const auto& mine : strong_suites()) {
        for (const auto& theirs : hub_offer) {
            if (theirs == mine) return mine;   // strongest common suite
        }
    }
    return "";                                 // no acceptable common suite
}

// ---- 2. key derivation (HKDF-SHA256, not the raw secret) ------------------
std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    int kl = keylen(suite);
    if (kl == 0) throw std::runtime_error("derive_key: unknown suite");
    std::vector<uint8_t> out(kl);

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) throw std::runtime_error("HKDF unavailable");
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    // info binds the key to the suite and the direction (context), so the two
    // directions (e.g. "c2s" and "s2c") get independent keys.
    std::string info = "smartlock-v2|" + suite + "|" + context;
    static const unsigned char salt[] = "smartlock-v2-hkdf-salt";

    OSSL_PARAM params[5];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0);
    params[i++] = OSSL_PARAM_construct_octet_string("key",
                   (void*)shared_secret.data(), shared_secret.size());
    params[i++] = OSSL_PARAM_construct_octet_string("salt", (void*)salt, sizeof(salt) - 1);
    params[i++] = OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size());
    params[i]   = OSSL_PARAM_construct_end();

    int rc = EVP_KDF_derive(ctx, out.data(), out.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (rc <= 0) throw std::runtime_error("HKDF derive failed");
    return out;
}

// ---- 3. nonce: unique 12 bytes per sequence number ------------------------
std::vector<uint8_t> make_nonce(uint64_t seqno) {
    std::vector<uint8_t> n(12, 0);             // 4-byte zero prefix ...
    for (int i = 0; i < 8; ++i)                // ... + 8-byte big-endian seqno
        n[11 - i] = (uint8_t)((seqno >> (8 * i)) & 0xff);
    return n;
}

// ---- 4 + 5. AEAD sealing, binding the sequence number ---------------------
// Record layout: [8-byte big-endian seqno] || [ciphertext] || [16-byte tag].
// The seqno header is also fed as AAD, so it cannot be altered undetected.
std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno,
                          const std::string& plaintext) {
    const EVP_CIPHER* c = cipher_for(key);
    auto nonce = make_nonce(seqno);
    auto aad   = seq_bytes(seqno);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    int len = 0;
    EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());   // AAD
    std::vector<uint8_t> ct(plaintext.size());
    EVP_EncryptUpdate(ctx, ct.data(), &len, (const unsigned char*)plaintext.data(), (int)plaintext.size());
    int ctlen = len;
    EVP_EncryptFinal_ex(ctx, ct.data() + len, &len); ctlen += len;
    ct.resize(ctlen);
    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> out = aad;                 // seqno header
    out.insert(out.end(), ct.begin(), ct.end());    // ciphertext
    out.insert(out.end(), tag.begin(), tag.end());  // tag
    return out;
}

std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    if (record.size() < 8 + 16) throw std::runtime_error("record too short");

    // Parse and check the sequence number first: reject replays / reorder.
    uint64_t seqno = 0;
    for (int i = 0; i < 8; ++i) seqno = (seqno << 8) | record[i];
    if (seqno != expected_seqno)
        throw std::runtime_error("unexpected sequence number (replay or out-of-order)");

    const EVP_CIPHER* c = cipher_for(key);
    auto nonce = make_nonce(seqno);
    std::vector<uint8_t> aad(record.begin(), record.begin() + 8);
    size_t bodylen = record.size() - 8 - 16;
    const uint8_t* ctp = record.data() + 8;
    const uint8_t* tagp = record.data() + 8 + bodylen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    int len = 0;
    EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size());   // AAD
    std::vector<uint8_t> pt(bodylen);
    EVP_DecryptUpdate(ctx, pt.data(), &len, ctp, (int)bodylen);
    int ptlen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tagp);
    int ok = EVP_DecryptFinal_ex(ctx, pt.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("AEAD authentication failed (tamper)");
    pt.resize(ptlen + len);
    return std::string(pt.begin(), pt.end());
}

}  // namespace sl2
