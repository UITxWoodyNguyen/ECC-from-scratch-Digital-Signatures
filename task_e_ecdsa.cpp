#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>

using namespace std;

#define ll int64_t
#define pb push_back

using Bytes = vector<uint8_t>;
static int g_failures = 0;

static void check(const char *name, bool ok) {
    printf(" [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_failures;
}

static void printBnBits(const char *label, const BIGNUM *x) {
    char *s = BN_bn2hex(x);
    if (s) {
        printf("  %-16s%d bits, 0x%.24s...\n", label, BN_num_bits(x), s);
        OPENSSL_free(s);
    }
}

static void printHex(const char *label, const uint8_t *p, size_t n, size_t maxShown = 24) {
    printf("  %-16s", label);
    for (size_t i = 0; i < n && i < maxShown; ++i) printf("%02x", p[i]);
    if (n > maxShown) printf("... (%zu bytes)", n);
    printf("\n");
}

static Bytes sha256(const Bytes &m) {
    Bytes h(32);
    unsigned int len = 0;
    EVP_Digest(m.data(), m.size(), h.data(), &len, EVP_sha256(), nullptr);
    return h;
}

static Bytes bytesOf(const char *s) {
    return Bytes(s, s + strlen(s));
}

struct Curve {
    EC_GROUP *g;
    const BIGNUM *n;
    BN_CTX *ctx;
};

static BIGNUM *bits2int(const Curve &C, const Bytes &h) {
    BIGNUM *e = BN_bin2bn(h.data(), static_cast<int>(h.size()), nullptr);
    int extra = static_cast<int>(h.size() * 8) - BN_num_bits(C.n);
    if (extra > 0) BN_rshift(e, e, extra);
    return e;
}

static void ecdsaSignWithK(const Curve &C, const BIGNUM *d, const Bytes &hash,
                           const BIGNUM *k, BIGNUM *r, BIGNUM *s) {
    BIGNUM *e = bits2int(C, hash), *x1 = BN_new(), *kinv = BN_new(), *t = BN_new();
    EC_POINT *R = EC_POINT_new(C.g);

    EC_POINT_mul(C.g, R, k, nullptr, nullptr, C.ctx);
    EC_POINT_get_affine_coordinates(C.g, R, x1, nullptr, C.ctx);
    BN_nnmod(r, x1, C.n, C.ctx);
    BN_mod_inverse(kinv, k, C.n, C.ctx);
    BN_mod_mul(t, r, d, C.n, C.ctx);
    BN_mod_add(t, t, e, C.n, C.ctx);
    BN_mod_mul(s, kinv, t, C.n, C.ctx);

    BN_free(e); BN_free(x1); BN_clear_free(kinv); BN_free(t); EC_POINT_free(R);
}

static void ecdsaSign(const Curve &C, const BIGNUM *d, const Bytes &hash, BIGNUM *r, BIGNUM *s) {
    BIGNUM *k = BN_new();
    do {
        BN_rand_range(k, C.n);
    } while (BN_is_zero(k));
    ecdsaSignWithK(C, d, hash, k, r, s);
    BN_clear_free(k);
}

static bool ecdsaVerify(const Curve &C, const EC_POINT *Q, const Bytes &hash,
                        const BIGNUM *r, const BIGNUM *s) {
    if (BN_is_zero(r) || BN_is_zero(s) || BN_is_negative(r) || BN_is_negative(s) ||
        BN_cmp(r, C.n) >= 0 || BN_cmp(s, C.n) >= 0) return false;
    BIGNUM *e = bits2int(C, hash), *w = BN_new(), *u1 = BN_new(), *u2 = BN_new(), *x = BN_new();
    EC_POINT *X = EC_POINT_new(C.g);

    BN_mod_inverse(w, s, C.n, C.ctx);
    BN_mod_mul(u1, e, w, C.n, C.ctx);
    BN_mod_mul(u2, r, w, C.n, C.ctx);
    EC_POINT_mul(C.g, X, u1, Q, u2, C.ctx);

    bool ok = false;
    if (EC_POINT_is_at_infinity(C.g, X) != 1) {
        EC_POINT_get_affine_coordinates(C.g, X, x, nullptr, C.ctx);
        BN_nnmod(x, x, C.n, C.ctx);
        ok = (BN_cmp(x, r) == 0);
    }
    BN_free(e); BN_free(w); BN_free(u1); BN_free(u2); BN_free(x); EC_POINT_free(X);
    return ok;
}

static Bytes toDer(const BIGNUM *r, const BIGNUM *s) {
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_dup(r), BN_dup(s));
    unsigned char *der = nullptr;
    int len = i2d_ECDSA_SIG(sig, &der);
    Bytes out(der, der + len);
    OPENSSL_free(der);
    ECDSA_SIG_free(sig);
    return out;
}

static void fromDer(const Bytes &der, BIGNUM *r, BIGNUM *s) {
    const unsigned char *p = der.data();
    ECDSA_SIG *sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    BN_copy(r, ECDSA_SIG_get0_r(sig));
    BN_copy(s, ECDSA_SIG_get0_s(sig));
    ECDSA_SIG_free(sig);
}

static Bytes evpSign(EVP_PKEY *key, const Bytes &msg) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestSignInit(md, nullptr, EVP_sha256(), nullptr, key);
    size_t len = 0;
    EVP_DigestSign(md, nullptr, &len, msg.data(), msg.size());
    Bytes sig(len);
    EVP_DigestSign(md, sig.data(), &len, msg.data(), msg.size());
    sig.resize(len);
    EVP_MD_CTX_free(md);
    return sig;
}

static bool evpVerify(EVP_PKEY *key, const Bytes &msg, const Bytes &sig) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, key);
    bool ok = (EVP_DigestVerify(md, sig.data(), sig.size(), msg.data(), msg.size()) == 1);
    if (!ok) ERR_clear_error();
    EVP_MD_CTX_free(md);
    return ok;
}

static void part1(const Curve &C, EVP_PKEY *key, const BIGNUM *d, const EC_POINT *Q) {
    printf("== Part 1: ECDSA P-256 / SHA-256 ==\n");
    Bytes M = bytesOf("Transfer 10 BTC to Bob"), h = sha256(M);
    BIGNUM *r = BN_new(), *s = BN_new(), *r2 = BN_new(), *s2 = BN_new();

    ecdsaSign(C, d, h, r, s);
    printBnBits("r", r);
    printBnBits("s", s);
    check("our verify accepts our signature", ecdsaVerify(C, Q, h, r, s));
    Bytes der = toDer(r, s);
    printHex("DER", der.data(), der.size(), 12);

    check("OpenSSL verifies our signature (DER)", evpVerify(key, M, der));

    Bytes evpSig = evpSign(key, M), evpSig2 = evpSign(key, M);
    fromDer(evpSig, r2, s2);
    check("our verify accepts OpenSSL's signature", ecdsaVerify(C, Q, h, r2, s2));
    check("randomized: two OpenSSL signatures differ", evpSig != evpSig2);
    check("changed message is rejected", !ecdsaVerify(C, Q, sha256(bytesOf("Transfer 99 BTC to Bob")), r, s));
    printf("\n");

    BN_free(r); BN_free(s); BN_free(r2); BN_free(s2);
}

static Bytes hmac(const Bytes &key, const Bytes &data) {
    Bytes out(32);
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &len);
    return out;
}

static Bytes cat(initializer_list<Bytes> parts) {
    Bytes r;
    for (const Bytes &p : parts) r.insert(r.end(), p.begin(), p.end());
    return r;
}

static BIGNUM *rfc6979Nonce(const Curve &C, const BIGNUM *d, const Bytes &h1) {
    Bytes x(32), hb(32);
    BN_bn2binpad(d, x.data(), 32);
    BIGNUM *e = bits2int(C, h1);
    BN_nnmod(e, e, C.n, C.ctx);
    BN_bn2binpad(e, hb.data(), 32);
    BN_free(e);

    Bytes V(32, 0x01), K(32, 0x00);
    K = hmac(K, cat({V, {0x00}, x, hb})); V = hmac(K, V);
    K = hmac(K, cat({V, {0x01}, x, hb})); V = hmac(K, V);

    while (true) {
        V = hmac(K, V);
        BIGNUM *k = bits2int(C, V);
        if (!BN_is_zero(k) && BN_cmp(k, C.n) < 0) {
            OPENSSL_cleanse(x.data(), 32);
            return k;
        }
        BN_free(k);
        K = hmac(K, cat({V, {0x00}}));
        V = hmac(K, V);
    }
}

static void part2Rfc6979(const Curve &C) {
    printf("== Part 2: deterministic nonce (RFC 6979, A.2.5) ==\n");
    BIGNUM *d = nullptr, *kExp = nullptr, *rExp = nullptr, *sExp = nullptr;
    BN_hex2bn(&d, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    BN_hex2bn(&kExp, "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    BN_hex2bn(&rExp, "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    BN_hex2bn(&sExp, "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    Bytes h = sha256(bytesOf("sample"));
    BIGNUM *k = rfc6979Nonce(C, d, h);
    check("k matches RFC 6979 test vector", BN_cmp(k, kExp) == 0);

    BIGNUM *r = BN_new(), *s = BN_new();
    ecdsaSignWithK(C, d, h, k, r, s);
    check("(r, s) match RFC 6979 test vector", BN_cmp(r, rExp) == 0 && BN_cmp(s, sExp) == 0);

    BIGNUM *k2 = rfc6979Nonce(C, d, sha256(bytesOf("test")));
    check("a different message gives a different k", BN_cmp(k, k2) != 0);
    printf("  (no RNG needed at signing time: the PS3 / Android failures cannot happen)\n\n");

    for (BIGNUM *v : {d, kExp, k, k2}) BN_clear_free(v);
    for (BIGNUM *v : {rExp, sExp, r, s}) BN_free(v);
}

static void part3Attacks(const Curve &C, EVP_PKEY *key, const BIGNUM *d, const EC_POINT *Q) {
    printf("== Part 3: attacks ==\n");
    Bytes h1 = sha256(bytesOf("message one")), h2 = sha256(bytesOf("message two"));
    BIGNUM *k = BN_new(), *r1 = BN_new(), *s1 = BN_new(), *r2 = BN_new(), *s2 = BN_new();
    BIGNUM *num = BN_new(), *den = BN_new(), *kRec = BN_new(), *dRec = BN_new(), *t = BN_new();

    BN_rand_range(k, C.n);
    ecdsaSignWithK(C, d, h1, k, r1, s1);
    ecdsaSignWithK(C, d, h2, k, r2, s2);
    check("both signatures share r (the reuse is visible)", BN_cmp(r1, r2) == 0);

    BIGNUM *e1 = bits2int(C, h1), *e2 = bits2int(C, h2);
    BN_mod_sub(num, e1, e2, C.n, C.ctx);
    BN_mod_sub(den, s1, s2, C.n, C.ctx);
    BN_mod_inverse(den, den, C.n, C.ctx);
    BN_mod_mul(kRec, num, den, C.n, C.ctx);

    BN_mod_mul(t, s1, kRec, C.n, C.ctx);
    BN_mod_sub(t, t, e1, C.n, C.ctx);
    BN_mod_inverse(den, r1, C.n, C.ctx);
    BN_mod_mul(dRec, t, den, C.n, C.ctx);

    check("attacker recovers k", BN_cmp(kRec, k) == 0);
    check("attacker recovers the private key d", BN_cmp(dRec, d) == 0);

    EC_POINT *Qrec = EC_POINT_new(C.g);
    EC_POINT_mul(C.g, Qrec, dRec, nullptr, nullptr, C.ctx);
    check("d_recovered * G == Q", EC_POINT_cmp(C.g, Qrec, Q, C.ctx) == 0);

    Bytes M = bytesOf("Transfer 10 BTC to Bob");
    BIGNUM *r = BN_new(), *s = BN_new(), *sNeg = BN_new();
    fromDer(evpSign(key, M), r, s);
    BN_sub(sNeg, C.n, s);
    Bytes twin = toDer(r, sNeg);
    check("(r, n - s) also verifies in OpenSSL", evpVerify(key, M, twin));
    printf("  -> a second valid signature without the key: signatures are not unique IDs\n");
    printf("     (Bitcoin requires low-s: s <= n/2)\n\n");

    for (BIGNUM *v : {k, kRec, dRec}) BN_clear_free(v);
    for (BIGNUM *v : {r1, s1, r2, s2, num, den, t, e1, e2, r, s, sNeg}) BN_free(v);
    EC_POINT_free(Qrec);
}

int main() {
    Curve C{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), nullptr, BN_CTX_new()};
    C.n = EC_GROUP_get0_order(C.g);

    EVP_PKEY *key = EVP_EC_gen("P-256");
    BIGNUM *d = nullptr;
    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &d);
    unsigned char q[65];
    size_t qLen = 0;
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, q, sizeof(q), &qLen);
    EC_POINT *Q = EC_POINT_new(C.g);
    EC_POINT_oct2point(C.g, Q, q, qLen, C.ctx);

    part1(C, key, d, Q);
    part2Rfc6979(C);
    part3Attacks(C, key, d, Q);

    EC_POINT_free(Q); BN_clear_free(d); EVP_PKEY_free(key);
    EC_GROUP_free(C.g); BN_CTX_free(C.ctx);

    printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
