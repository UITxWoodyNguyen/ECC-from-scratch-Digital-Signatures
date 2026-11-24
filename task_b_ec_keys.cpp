#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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

static Bytes fromHex(const char *h) {
    Bytes b;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
        char two[3] = {h[i], h[i + 1], 0};
        b.pb(static_cast<uint8_t>(strtoul(two, nullptr, 16)));
    }
    return b;
}

static Bytes keyId(EVP_PKEY *key) {
    uint8_t *der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0 || !der) return {};
    Bytes id(32);
    unsigned int outLen = 0;
    EVP_Digest(der, static_cast<size_t>(len), id.data(), &outLen, EVP_sha256(), nullptr);
    OPENSSL_free(der);
    return id;
}

static int spkiSize(EVP_PKEY *key) {
    return i2d_PUBKEY(key, nullptr);
}

static EVP_PKEY *genKey(const char *alg, const char *curve) {
    EVP_PKEY *k = curve ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve)
                        : EVP_PKEY_Q_keygen(nullptr, nullptr, alg);
    return k;
}

static void part1Generate() {
    printf("== Part 1: key generation ==\n");
    printf(" %-12s %-14s %5s %9s %s\n", "algorithm", "type", "bits", "SPKI size", "use");
    struct Row { const char *label; const char *alg; const char *curve; const char *use; };
    const Row rows[] = {
        {"P-256", "EC", "P-256", "ECDH, ECDSA"},
        {"P-384", "EC", "P-384", "ECDH, ECDSA"},
        {"secp256k1", "EC", "secp256k1", "ECDSA (Bitcoin)"},
        {"X25519", "X25519", nullptr, "key agreement only"},
        {"Ed25519", "ED25519", nullptr, "signatures only"},
        {"Ed448", "ED448", nullptr, "signatures only"},
    };
    for (const Row &r : rows) {
        EVP_PKEY *k = genKey(r.alg, r.curve);
        printf(" %-12s %-14s %5d %9d %s\n", r.label, EVP_PKEY_get0_type_name(k),
               EVP_PKEY_get_bits(k), spkiSize(k), r.use);
        EVP_PKEY_free(k);
    }
    EVP_PKEY *rsa = EVP_RSA_gen(3072);
    printf(" %-12s %-14s %5d %9d %s\n", "RSA-3072", "RSA", EVP_PKEY_get_bits(rsa),
           spkiSize(rsa), "same security as P-256");
    EVP_PKEY_free(rsa);
    printf("\n");
}

static void part2Inside() {
    printf("== Part 2: inside a P-256 key ==\n");
    EVP_PKEY *key = genKey("EC", "P-256");
    char curve[64];
    EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof(curve), nullptr);
    BIGNUM *d = nullptr;
    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &d);
    unsigned char pub[133];
    size_t pubLen = 0;
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &pubLen);

    printf(" curve           %s\n", curve);
    printf(" d               %d-bit secret scalar (not printed)\n", BN_num_bits(d));
    printHex("Q (encoded)", pub, pubLen, 20);

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curve));
    EC_POINT *Q = EC_POINT_new(grp), *Q2 = EC_POINT_new(grp);
    EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
    EC_POINT_oct2point(grp, Q2, pub, pubLen, ctx);

    check("stored public key == d * G", EC_POINT_cmp(grp, Q, Q2, ctx) == 0);
    check("1 <= d < n", !BN_is_zero(d) && BN_cmp(d, EC_GROUP_get0_order(grp)) < 0);
    printf("\n");

    EC_POINT_free(Q); EC_POINT_free(Q2); EC_GROUP_free(grp);
    BN_CTX_free(ctx); BN_clear_free(d); EVP_PKEY_free(key);
}

static void part3Raw() {
    printf("== Part 3: keys from raw values ==\n");
    Bytes seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    Bytes expectPub = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    EVP_PKEY *ed = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    Bytes pub(32);
    size_t len = pub.size();
    EVP_PKEY_get_raw_public_key(ed, pub.data(), &len);
    printHex("Ed25519 pub", pub.data(), len, 32);
    check("public key matches RFC 8032 test 1", pub == expectPub);

    EVP_PKEY *full = genKey("EC", "P-256");
    unsigned char q[65];
    size_t qLen = 0;
    EVP_PKEY_get_octet_string_param(full, OSSL_PKEY_PARAM_PUB_KEY, q, sizeof(q), &qLen);

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, q, qLen);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY_CTX *fctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY_fromdata_init(fctx);
    EVP_PKEY *pubOnly = nullptr;
    EVP_PKEY_fromdata(fctx, &pubOnly, EVP_PKEY_PUBLIC_KEY, params);
    check("key rebuilt from (curve, Q) equals the original", EVP_PKEY_eq(pubOnly, full) == 1);

    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pubOnly, nullptr);
    check("EVP_PKEY_public_check accepts it", EVP_PKEY_public_check(vctx) == 1);
    printf("\n");

    EVP_PKEY_CTX_free(vctx); EVP_PKEY_CTX_free(fctx);
    OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pubOnly); EVP_PKEY_free(full); EVP_PKEY_free(ed);
}

static void writeKeyFiles(EVP_PKEY *key, const string &prefix) {
    BIO *b = BIO_new_file((prefix + "_private.pem").c_str(), "wb");
    PEM_write_bio_PrivateKey(b, key, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(b);

    b = BIO_new_file((prefix + "_public.pem").c_str(), "wb");
    PEM_write_bio_PUBKEY(b, key);
    BIO_free(b);

    b = BIO_new_file((prefix + "_private.der").c_str(), "wb");
    i2d_PKCS8PrivateKey_bio(b, key, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(b);

    b = BIO_new_file((prefix + "_public.der").c_str(), "wb");
    i2d_PUBKEY_bio(b, key);
    BIO_free(b);
}

static EVP_PKEY *loadKey(const string &path, bool isPrivate, bool isPem) {
    BIO *b = BIO_new_file(path.c_str(), "rb");
    if (!b) return nullptr;
    EVP_PKEY *k = isPrivate
        ? (isPem ? PEM_read_bio_PrivateKey(b, nullptr, nullptr, nullptr) : d2i_PrivateKey_bio(b, nullptr))
        : (isPem ? PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr) : d2i_PUBKEY_bio(b, nullptr));
    BIO_free(b);
    return k;
}

static void part4Files() {
    printf("== Part 4: PEM and DER files ==\n");
    struct { const char *prefix; EVP_PKEY *key; } items[] = {
        {"ec", genKey("EC", "P-256")},
        {"ed25519", genKey("ED25519", nullptr)}
    };

    for (auto &it : items) {
        writeKeyFiles(it.key, it.prefix);
        string p = it.prefix;
        EVP_PKEY *a = loadKey(p + "_private.pem", true, true);
        EVP_PKEY *b = loadKey(p + "_private.der", true, false);
        EVP_PKEY *c = loadKey(p + "_public.pem", false, true);
        EVP_PKEY *d = loadKey(p + "_public.der", false, false);

        bool ok = EVP_PKEY_eq(a, c) == 1 && EVP_PKEY_eq(b, d) == 1 &&
                  EVP_PKEY_eq(a, d) == 1 && EVP_PKEY_eq(b, c) == 1 &&
                  EVP_PKEY_eq(a, it.key) == 1;
        printf(" wrote %s_{private,public}.{pem,der}\n", it.prefix);
        check((p + ": all four files hold the same key").c_str(), ok);

        Bytes id1 = keyId(c), id2 = keyId(d);
        check((p + ": key ID identical for PEM and DER").c_str(), id1 == id2);
        printHex("key ID", id1.data(), id1.size(), 16);

        for (EVP_PKEY *k : {a, b, c, d}) EVP_PKEY_free(k);
        EVP_PKEY_free(it.key);
    }
    printf("\n");
}

int main() {
    part1Generate();
    part2Inside();
    part3Raw();
    part4Files();
    printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
