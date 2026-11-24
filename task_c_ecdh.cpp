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
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>

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

static bool evpDerive(EVP_PKEY *mine, EVP_PKEY *peer, Bytes &Z) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, mine, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return false;
    }
    bool ok = (EVP_PKEY_derive_set_peer_ex(ctx, peer, 1) > 0);
    size_t len = 0;
    ok = ok && (EVP_PKEY_derive(ctx, nullptr, &len) > 0);
    if (ok) {
        Z.assign(len, 0);
        ok = (EVP_PKEY_derive(ctx, Z.data(), &len) > 0);
        Z.resize(len);
    }
    if (!ok) {
        ERR_clear_error();
        Z.clear();
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static EVP_PKEY *pubFromBytes(const char *curveOrNull, const Bytes &enc) {
    if (!curveOrNull) {
        EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, enc.data(), enc.size());
        if (!k) ERR_clear_error();
        return k;
    }
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curveOrNull, 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, enc.data(), enc.size());
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY *k = nullptr;
    if (EVP_PKEY_fromdata(ctx, &k, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        ERR_clear_error();
        k = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return k;
}

static Bytes encodedPub(EVP_PKEY *k) {
    uint8_t *p = nullptr;
    size_t len = EVP_PKEY_get1_encoded_public_key(k, &p);
    if (len == 0 || !p) return {};
    Bytes out(p, p + len);
    OPENSSL_free(p);
    return out;
}

static Bytes myEcdh(EVP_PKEY *mine, EVP_PKEY *peer) {
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *d = nullptr;
    EVP_PKEY_get_bn_param(mine, OSSL_PKEY_PARAM_PRIV_KEY, &d);
    Bytes q = encodedPub(peer);
    EC_POINT *Q = EC_POINT_new(g), *S = EC_POINT_new(g);
    BIGNUM *x = BN_new();

    EC_POINT_oct2point(g, Q, q.data(), q.size(), ctx);
    EC_POINT_mul(g, S, nullptr, Q, d, ctx);
    EC_POINT_get_affine_coordinates(g, S, x, nullptr, ctx);

    Bytes Z(32);
    BN_bn2binpad(x, Z.data(), 32);

    EC_POINT_free(Q); EC_POINT_free(S); EC_GROUP_free(g);
    BN_clear_free(d); BN_clear_free(x); BN_CTX_free(ctx);
    return Z;
}

static void part1Ecdh() {
    printf("== Part 1: ECDH on P-256 ==\n");
    EVP_PKEY *alice = EVP_EC_gen("P-256");
    EVP_PKEY *bob = EVP_EC_gen("P-256");

    Bytes zA = myEcdh(alice, bob);
    Bytes zB = myEcdh(bob, alice);
    Bytes zE;

    check("by hand: x(dA*QB) == x(dB*QA)", zA == zB);
    check("EVP_PKEY_derive gives the same Z", evpDerive(alice, bob, zE) && zE == zA);
    printHex("Z", zA.data(), zA.size(), 8);
    printf("\n");

    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
}

static void cswap(int swap, BIGNUM *a, BIGNUM *b) {
    if (swap) BN_swap(a, b);
}

static Bytes myX25519(const Bytes &kIn, const Bytes &uIn) {
    BN_CTX *ctx = BN_CTX_new();
    Bytes kb = kIn, ub = uIn;
    kb[0] &= 248; kb[31] &= 127; kb[31] |= 64;
    ub[31] &= 127;

    BIGNUM *p = BN_new();
    BIGNUM *k = BN_lebin2bn(kb.data(), 32, nullptr);
    BIGNUM *x1 = BN_lebin2bn(ub.data(), 32, nullptr);

    BIGNUM *x2 = BN_new(), *z2 = BN_new(), *x3 = BN_new(), *z3 = BN_new(), *a24 = BN_new();
    BIGNUM *A = BN_new(), *AA = BN_new(), *B = BN_new(), *BB = BN_new(), *E = BN_new();
    BIGNUM *C = BN_new(), *D = BN_new(), *DA = BN_new(), *CB = BN_new(), *t = BN_new();

    BN_set_word(p, 1); BN_lshift(p, p, 255); BN_sub_word(p, 19);
    BN_nnmod(x1, x1, p, ctx);
    BN_set_word(a24, 121665);
    BN_one(x2); BN_zero(z2);
    BN_copy(x3, x1); BN_one(z3);

    int swap = 0;
    for (int i = 254; i >= 0; --i) {
        int bit = BN_is_bit_set(k, i);
        swap ^= bit;
        cswap(swap, x2, x3); cswap(swap, z2, z3);
        swap = bit;

        BN_mod_add(A, x2, z2, p, ctx); BN_mod_sqr(AA, A, p, ctx);
        BN_mod_sub(B, x2, z2, p, ctx); BN_mod_sqr(BB, B, p, ctx);
        BN_mod_sub(E, AA, BB, p, ctx);
        BN_mod_add(C, x3, z3, p, ctx); BN_mod_sub(D, x3, z3, p, ctx);
        BN_mod_mul(DA, D, A, p, ctx); BN_mod_mul(CB, C, B, p, ctx);
        BN_mod_add(t, DA, CB, p, ctx); BN_mod_sqr(x3, t, p, ctx);
        BN_mod_sub(t, DA, CB, p, ctx); BN_mod_sqr(t, t, p, ctx);
        BN_mod_mul(z3, x1, t, p, ctx);
        BN_mod_mul(x2, AA, BB, p, ctx);
        BN_mod_mul(t, a24, E, p, ctx); BN_mod_add(t, AA, t, p, ctx);
        BN_mod_mul(z2, E, t, p, ctx);
    }
    cswap(swap, x2, x3); cswap(swap, z2, z3);

    BN_copy(t, p); BN_sub_word(t, 2);
    BN_mod_exp(z2, z2, t, p, ctx);
    BN_mod_mul(x2, x2, z2, p, ctx);

    Bytes out(32);
    BN_bn2lebinpad(x2, out.data(), 32);

    for (BIGNUM *v : {p, x1, x3, z3, a24, A, AA, B, BB, E, C, D, DA, CB, t}) BN_free(v);
    BN_clear_free(k); BN_clear_free(x2); BN_clear_free(z2);
    BN_CTX_free(ctx);
    return out;
}

static void part2X25519() {
    printf("== Part 2: X25519 (RFC 7748) ==\n");
    Bytes aPriv = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    Bytes bPriv = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    Bytes aPubE = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    Bytes bPubE = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    Bytes zE = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    Bytes base(32, 0);
    base[0] = 9;

    Bytes aPub = myX25519(aPriv, base), bPub = myX25519(bPriv, base);
    check("by hand: Alice's public key matches RFC 7748", aPub == aPubE);
    check("by hand: Bob's public key matches RFC 7748", bPub == bPubE);

    Bytes z1 = myX25519(aPriv, bPub), z2 = myX25519(bPriv, aPub);
    printHex("shared K", z1.data(), z1.size(), 32);
    check("by hand: both sides get the RFC shared secret", z1 == zE && z2 == zE);

    EVP_PKEY *A = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, aPriv.data(), 32);
    EVP_PKEY *Bp = pubFromBytes(nullptr, bPubE);
    Bytes z3;
    check("EVP_PKEY_derive gives the same secret", evpDerive(A, Bp, z3) && z3 == zE);

    Bytes zero(32, 0);
    check("by hand: X25519(k, 0) = 00...00 (contributes nothing secret)", myX25519(aPriv, zero) == zero);

    EVP_PKEY *bad = pubFromBytes(nullptr, zero);
    check("OpenSSL refuses to derive from the low-order point", !evpDerive(A, bad, z3));
    printf("\n");

    EVP_PKEY_free(A); EVP_PKEY_free(Bp); EVP_PKEY_free(bad);
}

static Bytes hkdf(const Bytes &ikm, const Bytes &info, size_t L) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm.data(), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info.data(), info.size()),
        OSSL_PARAM_construct_end()
    };
    Bytes out(L);
    EVP_KDF_derive(kctx, out.data(), L, params);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return out;
}

static Bytes kdfInfo(const Bytes &E, const Bytes &QR) {
    const char label[] = "LAB03-ECIES-HKDF-SHA256-AES256GCM-v1";
    Bytes info(label, label + strlen(label));
    info.pb(0x00);
    info.insert(info.end(), E.begin(), E.end());
    info.insert(info.end(), QR.begin(), QR.end());
    return info;
}

static bool gcm(bool enc, const Bytes &key, const Bytes &nonce, const Bytes &aad,
                const Bytes &in, Bytes &out, Bytes &tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex2(ctx, EVP_aes_256_gcm(), key.data(), nonce.data(), enc ? 1 : 0, nullptr);
    int len = 0;
    EVP_CipherUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
    out.assign(in.size() + 16, 0);
    EVP_CipherUpdate(ctx, out.data(), &len, in.data(), static_cast<int>(in.size()));
    int total = len;
    if (!enc) EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
    bool ok = (EVP_CipherFinal_ex(ctx, out.data() + total, &len) == 1);
    if (enc) {
        tag.assign(16, 0);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());
    }
    if (ok) out.resize(total + len);
    else { ERR_clear_error(); out.clear(); }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static void putU16(Bytes &b, uint16_t v) { b.pb(v >> 8); b.pb(v & 0xff); }
static void putU64(Bytes &b, uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) b.pb((v >> s) & 0xff);
}

static Bytes eciesSeal(EVP_PKEY *recipient, const char *curveOrNull, const Bytes &msg) {
    EVP_PKEY *eph = curveOrNull ? EVP_EC_gen(curveOrNull)
                               : EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    Bytes Z, E = encodedPub(eph), QR = encodedPub(recipient);
    evpDerive(eph, recipient, Z);
    EVP_PKEY_free(eph);

    Bytes K = hkdf(Z, kdfInfo(E, QR), 32);
    Bytes nonce(12), C, T;
    RAND_bytes(nonce.data(), 12);

    Bytes h = {'L', '3', 'P', 'K', 0x01, static_cast<uint8_t>(curveOrNull ? 0x03 : 0x04), 0x00, 0x00};
    putU16(h, static_cast<uint16_t>(E.size()));
    h.insert(h.end(), E.begin(), E.end());
    h.insert(h.end(), nonce.begin(), nonce.end());
    putU64(h, msg.size());

    gcm(true, K, nonce, h, msg, C, T);
    OPENSSL_cleanse(Z.data(), Z.size());
    OPENSSL_cleanse(K.data(), K.size());

    Bytes pkg = h;
    pkg.insert(pkg.end(), C.begin(), C.end());
    pkg.insert(pkg.end(), T.begin(), T.end());
    return pkg;
}

static bool eciesOpen(EVP_PKEY *priv, const char *curveOrNull, const Bytes &pkg, Bytes &msg, string &why) {
    if (pkg.size() < 10 || memcmp(pkg.data(), "L3PK\x01", 5) != 0) {
        why = "bad header";
        return false;
    }
    size_t elen = static_cast<size_t>((pkg[8] << 8) | pkg[9]);
    size_t hlen = 10 + elen + 12 + 8;
    if (pkg.size() < hlen + 16) {
        why = "truncated";
        return false;
    }
    Bytes E(pkg.begin() + 10, pkg.begin() + 10 + elen);
    Bytes nonce(pkg.begin() + 10 + elen, pkg.begin() + 22 + elen);
    Bytes h(pkg.begin(), pkg.begin() + hlen);
    Bytes C(pkg.begin() + hlen, pkg.end() - 16);
    Bytes T(pkg.end() - 16, pkg.end());

    EVP_PKEY *ephPub = pubFromBytes(curveOrNull, E);
    if (!ephPub) {
        why = "invalid ephemeral public key";
        return false;
    }
    Bytes Z;
    bool ok = evpDerive(priv, ephPub, Z);
    EVP_PKEY_free(ephPub);
    if (!ok) {
        why = "key agreement failed";
        return false;
    }
    Bytes K = hkdf(Z, kdfInfo(E, encodedPub(priv)), 32);
    ok = gcm(false, K, nonce, h, C, msg, T);
    OPENSSL_cleanse(Z.data(), Z.size());
    OPENSSL_cleanse(K.data(), K.size());
    why = ok ? "ok" : "decryption failed";
    return ok;
}

static void part3Ecies() {
    printf("== Part 3: ECIES (ephemeral ECDH + HKDF + AES-256-GCM) ==\n");
    const char *text = "The vault code is 7-3-1-9.";
    Bytes msg(text, text + strlen(text)), out;
    string why;

    struct { const char *curve; const char *name; } modes[] = {
        {"P-256", "P-256 "},
        {nullptr, "X25519"}
    };

    for (auto &m : modes) {
        EVP_PKEY *bob = m.curve ? EVP_EC_gen(m.curve) : EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        Bytes pkg = eciesSeal(bob, m.curve, msg), pkg2 = eciesSeal(bob, m.curve, msg);
        printf(" %s package: %zu bytes (header %zu + ct %zu + tag 16)\n", m.name,
               pkg.size(), pkg.size() - msg.size() - 16, msg.size());

        check((string(m.name) + ": round trip").c_str(),
              eciesOpen(bob, m.curve, pkg, out, why) && out == msg);
        check((string(m.name) + ": two seals differ (fresh ephemeral key)").c_str(),
              pkg != pkg2);

        Bytes bad = pkg;
        bad[12] ^= 0x01;
        bool opened = eciesOpen(bob, m.curve, bad, out, why);
        printf(" flip a byte of E -> %s\n", why.c_str());
        check((string(m.name) + ": modified E is rejected").c_str(), !opened);

        bad = pkg;
        bad[bad.size() - 1] ^= 0x01;
        opened = eciesOpen(bob, m.curve, bad, out, why);
        printf(" flip a tag byte -> %s\n", why.c_str());
        check((string(m.name) + ": modified tag is rejected").c_str(), !opened);

        EVP_PKEY *eve = m.curve ? EVP_EC_gen(m.curve) : EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        check((string(m.name) + ": wrong private key cannot open").c_str(),
              !eciesOpen(eve, m.curve, pkg, out, why));

        EVP_PKEY_free(bob);
        EVP_PKEY_free(eve);
    }
    printf("\n");
}

int main() {
    part1Ecdh();
    part2X25519();
    part3Ecies();
    printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
