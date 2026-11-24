#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

using namespace std;

#define ll int64_t
#define pb push_back

using Bytes = vector<uint8_t>;
static int g_failures = 0;

static void check(const char *name, bool ok) {
    printf(" [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

static void printHex(const char *label, const uint8_t *p, size_t n, size_t maxShown = 24) {
    printf("  %-16s", label);
    for (size_t i = 0; i < n && i < maxShown; ++i) printf("%02x", p[i]);
    if (n > maxShown) printf("... (%zu bytes)", n);
    printf("\n");
}

static const size_t hLen = 32;

static Bytes sha256(const Bytes &m) {
    Bytes h(hLen);
    unsigned int len = 0;
    EVP_Digest(m.data(), m.size(), h.data(), &len, EVP_sha256(), nullptr);
    return h;
}

static Bytes mgf1(const Bytes &seed, size_t maskLen) {
    Bytes t;
    for (uint32_t c = 0; t.size() < maskLen; ++c) {
        Bytes blk = seed;
        for (int s = 24; s >= 0; s -= 8) blk.pb(static_cast<uint8_t>(c >> s));
        Bytes h = sha256(blk);
        t.insert(t.end(), h.begin(), h.end());
    }
    t.resize(maskLen);
    return t;
}

static Bytes bytesOf(const char *s) {
    return Bytes(s, s + strlen(s));
}

static Bytes rsaRaw(const Bytes &x, const BIGNUM *exp, const BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *xi = BN_bin2bn(x.data(), static_cast<int>(x.size()), nullptr);
    BIGNUM *yi = BN_new();
    BN_mod_exp(yi, xi, exp, n, ctx);
    Bytes y(static_cast<size_t>(BN_num_bytes(n)));
    BN_bn2binpad(yi, y.data(), static_cast<int>(y.size()));
    BN_free(xi); BN_free(yi); BN_CTX_free(ctx);
    return y;
}

static BIGNUM *intOf(const char *text) {
    return BN_bin2bn(reinterpret_cast<const unsigned char *>(text), static_cast<int>(strlen(text)), nullptr);
}

static void part1Textbook(const BIGNUM *n, const BIGNUM *e, const BIGNUM *d) {
    printf("== Part 1: textbook RSA signatures, RSA-2048 (INSECURE) ==\n");
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *v = BN_new(), *s = BN_new(), *mf = BN_new(), *r = BN_new(), *rinv = BN_new(),
           *mBlind = BN_new(), *sBlind = BN_new(), *t = BN_new();

    auto sign = [&](BIGNUM *out, const BIGNUM *m) { BN_mod_exp(out, m, d, n, ctx); };
    auto verify = [&](const BIGNUM *m, const BIGNUM *sig) {
        BN_mod_exp(v, sig, e, n, ctx);
        return (BN_cmp(v, m) == 0);
    };

    BIGNUM *m = intOf("I, Alice, owe Bob 100 USD.");
    sign(s, m);
    check("textbook signature verifies", verify(m, s));

    BN_rand_range(s, n);
    BN_mod_exp(mf, s, e, n, ctx);
    check("forgery 1: (s^e mod n, s) verifies without d", verify(mf, s));

    BIGNUM *target = intOf("I, Alice, owe Mallory 1000000 USD.");
    do { BN_rand_range(r, n); } while (!BN_mod_inverse(rinv, r, n, ctx));
    BN_mod_exp(t, r, e, n, ctx);
    BN_mod_mul(mBlind, target, t, n, ctx);

    sign(sBlind, mBlind);
    BN_mod_mul(s, sBlind, rinv, n, ctx);
    check("forgery 2: Alice never saw m*, yet (m*, s) verifies", verify(target, s));
    printf("  -> fix: sign a padded encoding of H(M) (PKCS#1 v1.5 or PSS), never M itself\n\n");

    for (BIGNUM *x : {v, s, mf, r, rinv, mBlind, sBlind, t, m, target}) BN_free(x);
    BN_CTX_free(ctx);
}

static void setPadding(EVP_PKEY_CTX *pctx, bool pss) {
    EVP_PKEY_CTX_set_rsa_padding(pctx, pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING);
    if (pss) {
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());
    }
}

static Bytes evpSign(EVP_PKEY *key, const Bytes &msg, bool pss) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_DigestSignInit(md, &pctx, EVP_sha256(), nullptr, key);
    setPadding(pctx, pss);
    size_t len = 0;
    EVP_DigestSign(md, nullptr, &len, msg.data(), msg.size());
    Bytes sig(len);
    EVP_DigestSign(md, sig.data(), &len, msg.data(), msg.size());
    sig.resize(len);
    EVP_MD_CTX_free(md);
    return sig;
}

static bool evpVerify(EVP_PKEY *key, const Bytes &msg, const Bytes &sig, bool pss) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_DigestVerifyInit(md, &pctx, EVP_sha256(), nullptr, key);
    setPadding(pctx, pss);
    bool ok = (EVP_DigestVerify(md, sig.data(), sig.size(), msg.data(), msg.size()) == 1);
    if (!ok) ERR_clear_error();
    EVP_MD_CTX_free(md);
    return ok;
}

static const unsigned char kSha256Prefix[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static Bytes emsaPkcs1(const Bytes &M, size_t k) {
    Bytes T(kSha256Prefix, kSha256Prefix + 19), h = sha256(M);
    T.insert(T.end(), h.begin(), h.end());
    if (k < T.size() + 11) return {};
    Bytes EM;
    EM.reserve(k);
    EM.pb(0x00);
    EM.pb(0x01);
    EM.insert(EM.end(), k - T.size() - 3, 0xFF);
    EM.pb(0x00);
    EM.insert(EM.end(), T.begin(), T.end());
    return EM;
}

static void part2Pkcs1(EVP_PKEY *key, const BIGNUM *n, const BIGNUM *e, const BIGNUM *d) {
    printf("== Part 2: RSASSA-PKCS1-v1_5 (SHA-256) ==\n");
    const size_t k = static_cast<size_t>(BN_num_bytes(n));
    Bytes M = bytesOf("Pay 100 USD to Alice");
    Bytes EM = emsaPkcs1(M, k);
    printHex("EM", EM.data(), EM.size(), 24);
    Bytes sMine = rsaRaw(EM, d, n);
    Bytes sEvp = evpSign(key, M, false);

    check("our signature == EVP_DigestSign (byte for byte)", sMine == sEvp);
    check("deterministic: signing twice gives the same signature", evpSign(key, M, false) == sEvp);
    check("OpenSSL verifies our signature", evpVerify(key, M, sMine, false));
    check("our verification: s^e mod n == EMSA-PKCS1(M)", rsaRaw(sEvp, e, n) == EM);

    Bytes M2 = bytesOf("Pay 900 USD to Alice");
    check("signature does not verify for a changed message", !evpVerify(key, M2, sMine, false));
    printf("\n");
}

static Bytes emsaPssEncode(const Bytes &M, size_t emBits, size_t sLen) {
    const size_t emLen = (emBits + 7) / 8;
    Bytes mHash = sha256(M), salt(sLen);
    RAND_bytes(salt.data(), static_cast<int>(sLen));
    Bytes Mp(8, 0x00);
    Mp.insert(Mp.end(), mHash.begin(), mHash.end());
    Mp.insert(Mp.end(), salt.begin(), salt.end());
    Bytes H = sha256(Mp);
    Bytes DB(emLen - sLen - hLen - 2, 0x00);
    DB.pb(0x01);
    DB.insert(DB.end(), salt.begin(), salt.end());
    Bytes mask = mgf1(H, emLen - hLen - 1);
    for (size_t i = 0; i < DB.size(); ++i) DB[i] ^= mask[i];
    DB[0] &= static_cast<unsigned char>(0xFF >> (8 * emLen - emBits));
    Bytes EM = DB;
    EM.insert(EM.end(), H.begin(), H.end());
    EM.pb(0xBC);
    return EM;
}

static bool emsaPssVerify(const Bytes &M, const Bytes &EMin, size_t emBits, size_t sLen) {
    const size_t emLen = (emBits + 7) / 8;
    if (EMin.size() < emLen) return false;
    Bytes EM(EMin.end() - emLen, EMin.end());
    if (EM.back() != 0xBC) return false;
    Bytes DB(EM.begin(), EM.begin() + (emLen - hLen - 1));
    Bytes H(EM.end() - hLen - 1, EM.end() - 1);
    unsigned char topMask = static_cast<unsigned char>(0xFF << (8 - (8 * emLen - emBits)));
    if (8 * emLen > emBits && (DB[0] & topMask)) return false;
    Bytes mask = mgf1(H, DB.size());
    for (size_t i = 0; i < DB.size(); ++i) DB[i] ^= mask[i];
    DB[0] &= static_cast<unsigned char>(0xFF >> (8 * emLen - emBits));
    size_t ps = emLen - hLen - sLen - 2;
    for (size_t i = 0; i < ps; ++i) if (DB[i] != 0x00) return false;
    if (DB[ps] != 0x01) return false;
    Bytes salt(DB.end() - sLen, DB.end()), mHash = sha256(M), Mp(8, 0x00);
    Mp.insert(Mp.end(), mHash.begin(), mHash.end());
    Mp.insert(Mp.end(), salt.begin(), salt.end());
    return sha256(Mp) == H;
}

static void part3Pss(EVP_PKEY *key, const BIGNUM *n, const BIGNUM *e, const BIGNUM *d) {
    printf("== Part 3: RSASSA-PSS (SHA-256, sLen = 32) ==\n");
    const size_t emBits = static_cast<size_t>(BN_num_bits(n) - 1);
    Bytes M = bytesOf("Pay 100 USD to Alice");
    Bytes EM = emsaPssEncode(M, emBits, 32);
    printHex("EM", EM.data(), EM.size(), 24);
    Bytes sMine = rsaRaw(EM, d, n);
    check("OpenSSL verifies our PSS signature", evpVerify(key, M, sMine, true));

    Bytes sEvp = evpSign(key, M, true), sEvp2 = evpSign(key, M, true);
    check("our EMSA-PSS-VERIFY accepts OpenSSL's signature",
          emsaPssVerify(M, rsaRaw(sEvp, e, n), emBits, 32));
    check("randomized: two PSS signatures of M differ", sEvp != sEvp2);
    check("both verify", evpVerify(key, M, sEvp, true) && evpVerify(key, M, sEvp2, true));
    check("a PSS signature is not a valid PKCS#1 v1.5 signature", !evpVerify(key, M, sEvp, false));

    Bytes bad = sEvp;
    bad[5] ^= 0x01;
    check("modified signature is rejected", !evpVerify(key, M, bad, true));
    printf("\n");
}

int main() {
    EVP_PKEY *key = EVP_RSA_gen(2048);
    BIGNUM *n = nullptr, *e = nullptr, *d = nullptr;
    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d);

    part1Textbook(n, e, d);
    part2Pkcs1(key, n, e, d);
    part3Pss(key, n, e, d);

    BN_free(n); BN_free(e); BN_clear_free(d);
    EVP_PKEY_free(key);

    printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
