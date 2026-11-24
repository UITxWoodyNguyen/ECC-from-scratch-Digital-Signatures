#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <cstdio>
#include <cstdlib>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
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

static Bytes bytesOf(const char *s) {
    return Bytes(s, s + strlen(s));
}

static Bytes sha512(const Bytes &m) {
    Bytes h(64);
    unsigned int len = 0;
    EVP_Digest(m.data(), m.size(), h.data(), &len, EVP_sha512(), nullptr);
    return h;
}

static Bytes cat(initializer_list<Bytes> parts) {
    Bytes r;
    for (const Bytes &p : parts) r.insert(r.end(), p.begin(), p.end());
    return r;
}

struct Ed {
    BIGNUM *p;
    BIGNUM *d;
    BIGNUM *L;
    BN_CTX *ctx;
};

struct EPt {
    BIGNUM *x;
    BIGNUM *y;
};

static EPt newPt() {
    EPt P{BN_new(), BN_new()};
    BN_zero(P.x);
    BN_one(P.y);
    return P;
}

static void freePt(EPt &P) {
    if (P.x) BN_free(P.x);
    if (P.y) BN_free(P.y);
    P.x = nullptr;
    P.y = nullptr;
}

static void edAdd(const Ed &E, EPt &R, const EPt &P, const EPt &Q) {
    BIGNUM *a = BN_new(), *b = BN_new(), *c = BN_new(), *t = BN_new(), *x3 = BN_new(), *y3 = BN_new();

    BN_mod_mul(a, P.x, Q.y, E.p, E.ctx);
    BN_mod_mul(b, Q.x, P.y, E.p, E.ctx);
    BN_mod_add(x3, a, b, E.p, E.ctx);

    BN_mod_mul(a, P.y, Q.y, E.p, E.ctx);
    BN_mod_mul(b, P.x, Q.x, E.p, E.ctx);
    BN_mod_add(y3, a, b, E.p, E.ctx);

    BN_mod_mul(c, b, a, E.p, E.ctx);
    BN_mod_mul(c, c, E.d, E.p, E.ctx);

    BN_one(t);
    BN_mod_add(t, t, c, E.p, E.ctx);
    BN_mod_inverse(t, t, E.p, E.ctx);
    BN_mod_mul(x3, x3, t, E.p, E.ctx);

    BN_one(t);
    BN_mod_sub(t, t, c, E.p, E.ctx);
    BN_mod_inverse(t, t, E.p, E.ctx);
    BN_mod_mul(y3, y3, t, E.p, E.ctx);

    BN_copy(R.x, x3);
    BN_copy(R.y, y3);

    for (BIGNUM *v : {a, b, c, t, x3, y3}) BN_free(v);
}

static void edMul(const Ed &E, EPt &R, const BIGNUM *k, const EPt &P) {
    EPt acc = newPt();
    for (int i = BN_num_bits(k) - 1; i >= 0; --i) {
        edAdd(E, acc, acc, acc);
        if (BN_is_bit_set(k, i)) edAdd(E, acc, acc, P);
    }
    BN_copy(R.x, acc.x);
    BN_copy(R.y, acc.y);
    freePt(acc);
}

static Bytes encode(const EPt &P) {
    Bytes out(32);
    BN_bn2lebinpad(P.y, out.data(), 32);
    if (BN_is_odd(P.x)) out[31] |= 0x80;
    return out;
}

static bool decode(const Ed &E, const Bytes &in, EPt &P) {
    if (in.size() != 32) return false;
    Bytes b = in;
    int sign = b[31] >> 7;
    b[31] &= 0x7F;

    BIGNUM *y = BN_lebin2bn(b.data(), 32, nullptr), *u = BN_new(), *v = BN_new(), *x = BN_new();
    bool ok = (BN_cmp(y, E.p) < 0);
    if (ok) {
        BN_mod_sqr(u, y, E.p, E.ctx);
        BN_mod_mul(v, u, E.d, E.p, E.ctx);
        BN_add_word(v, 1);
        BN_sub_word(u, 1);
        BN_nnmod(u, u, E.p, E.ctx);
        BN_mod_inverse(v, v, E.p, E.ctx);
        BN_mod_mul(u, u, v, E.p, E.ctx);
        if (!BN_mod_sqrt(x, u, E.p, E.ctx)) {
            ERR_clear_error();
            ok = false;
        } else {
            BN_mod_sqr(v, x, E.p, E.ctx);
            ok = (BN_cmp(v, u) == 0 && !(BN_is_zero(x) && sign));
            if (ok && BN_is_odd(x) != sign) BN_sub(x, E.p, x);
        }
    }
    if (ok) {
        BN_copy(P.x, x);
        BN_copy(P.y, y);
    }
    BN_free(y); BN_free(u); BN_free(v); BN_free(x);
    return ok;
}

static BIGNUM *leModL(const Ed &E, const Bytes &h) {
    BIGNUM *r = BN_lebin2bn(h.data(), static_cast<int>(h.size()), nullptr);
    BN_nnmod(r, r, E.L, E.ctx);
    return r;
}

struct EdKey { Bytes A; BIGNUM *s; Bytes prefix; };

static EdKey edKeyFromSeed(const Ed &E, const EPt &B, const Bytes &seed) {
    Bytes h = sha512(seed);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    EdKey k{{}, BN_lebin2bn(h.data(), 32, nullptr), Bytes(h.begin() + 32, h.end())};
    EPt A = newPt();
    edMul(E, A, k.s, B);
    k.A = encode(A);
    freePt(A);
    OPENSSL_cleanse(h.data(), h.size());
    return k;
}

static Bytes edSign(const Ed &E, const EPt &B, const EdKey &key, const Bytes &M) {
    BIGNUM *r = leModL(E, sha512(cat({key.prefix, M})));
    EPt R = newPt();
    edMul(E, R, r, B);
    Bytes Renc = encode(R);
    BIGNUM *k = leModL(E, sha512(cat({Renc, key.A, M}))), *S = BN_new();
    BN_mod_mul(S, k, key.s, E.L, E.ctx);
    BN_mod_add(S, S, r, E.L, E.ctx);
    Bytes sig = Renc, Sb(32);
    BN_bn2lebinpad(S, Sb.data(), 32);
    sig.insert(sig.end(), Sb.begin(), Sb.end());
    BN_clear_free(r); BN_free(k); BN_free(S); freePt(R);
    return sig;
}

static bool edVerify(const Ed &E, const EPt &B, const Bytes &Aenc, const Bytes &M, const Bytes &sig) {
    if (sig.size() != 64) return false;
    Bytes Renc(sig.begin(), sig.begin() + 32), Sb(sig.begin() + 32, sig.end());
    EPt A = newPt(), R = newPt(), lhs = newPt(), rhs = newPt();
    BIGNUM *S = BN_lebin2bn(Sb.data(), 32, nullptr);
    bool ok = (BN_cmp(S, E.L) < 0 && decode(E, Aenc, A) && decode(E, Renc, R));
    if (ok) {
        BIGNUM *k = leModL(E, sha512(cat({Renc, Aenc, M})));
        edMul(E, lhs, S, B);
        edMul(E, rhs, k, A);
        edAdd(E, rhs, rhs, R);
        ok = (BN_cmp(lhs.x, rhs.x) == 0 && BN_cmp(lhs.y, rhs.y) == 0);
        BN_free(k);
    }
    BN_free(S); freePt(A); freePt(R); freePt(lhs); freePt(rhs);
    return ok;
}

static Bytes evpSign(EVP_PKEY *key, const EVP_MD *md, int rsaPad, const Bytes &msg) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_DigestSignInit(mctx, &pctx, md, nullptr, key);
    if (rsaPad) EVP_PKEY_CTX_set_rsa_padding(pctx, rsaPad);
    size_t len = 0;
    EVP_DigestSign(mctx, nullptr, &len, msg.data(), msg.size());
    Bytes sig(len);
    EVP_DigestSign(mctx, sig.data(), &len, msg.data(), msg.size());
    sig.resize(len);
    EVP_MD_CTX_free(mctx);
    return sig;
}

static bool evpVerify(EVP_PKEY *key, const EVP_MD *md, int rsaPad, const Bytes &msg, const Bytes &sig) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_DigestVerifyInit(mctx, &pctx, md, nullptr, key);
    if (rsaPad) EVP_PKEY_CTX_set_rsa_padding(pctx, rsaPad);
    bool ok = (EVP_DigestVerify(mctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1);
    if (!ok) ERR_clear_error();
    EVP_MD_CTX_free(mctx);
    return ok;
}

static void part1And2(const Ed &E, const EPt &B) {
    printf("== Part 1: Ed25519 by hand (RFC 8032) ==\n");
    Bytes seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    Bytes expA = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    Bytes expSig = fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                           "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    EdKey key = edKeyFromSeed(E, B, seed);
    check("A = sB matches RFC 8032 test 1", key.A == expA);
    Bytes sig = edSign(E, B, key, Bytes{});
    printHex("sig(\"\")", sig.data(), sig.size(), 16);
    check("signature of the empty message matches RFC 8032 test 1", sig == expSig);
    check("our verify accepts it", edVerify(E, B, key.A, Bytes{}, sig));

    EVP_PKEY *ossl = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), 32);
    Bytes M = bytesOf("I, Alice, owe Bob 5 USD.");
    Bytes mine = edSign(E, B, key, M), theirs = evpSign(ossl, nullptr, 0, M);
    check("our signature == OpenSSL's (deterministic, byte for byte)", mine == theirs);
    check("OpenSSL verifies our signature", evpVerify(ossl, nullptr, 0, M, mine));
    check("changed message is rejected", !edVerify(E, B, key.A, bytesOf("I, Alice, owe Bob 500 USD."), mine));

    printf("\n== Part 2: malleability ==\n");
    BIGNUM *S = BN_lebin2bn(mine.data() + 32, 32, nullptr);
    BN_add(S, S, E.L);
    Bytes twin = mine;
    BN_bn2lebinpad(S, twin.data() + 32, 32);
    check("our verify rejects (R, S + L)", !edVerify(E, B, key.A, M, twin));
    check("OpenSSL rejects (R, S + L)", !evpVerify(ossl, nullptr, 0, M, twin));
    printf("  -> unlike ECDSA's (r, n - s), Ed25519 signatures are unique when S < L is enforced\n\n");

    BN_free(S); BN_clear_free(key.s); EVP_PKEY_free(ossl);
}

static void part3Compare() {
    printf("== Part 3: all Lab 3 signature algorithms ==\n");
    printf(" %-20s %8s %8s %10s %10s\n", "algorithm", "SPKI (B)", "sig (B)", "sign/s", "verify/s");
    struct Alg {
        const char *name; const char *type; const char *curve; unsigned bits;
        const EVP_MD *md; int pad;
    };
    const Alg algs[] = {
        {"RSA-2048 PKCS1 v1.5", "RSA", nullptr, 2048, EVP_sha256(), RSA_PKCS1_PADDING},
        {"RSA-3072 PSS", "RSA", nullptr, 3072, EVP_sha256(), RSA_PKCS1_PSS_PADDING},
        {"ECDSA P-256", "EC", "P-256", 0, EVP_sha256(), 0},
        {"ECDSA P-384", "EC", "P-384", 0, EVP_sha384(), 0},
        {"ECDSA secp256k1", "EC", "secp256k1", 0, EVP_sha256(), 0},
        {"Ed25519", "ED25519", nullptr, 0, nullptr, 0},
        {"Ed448", "ED448", nullptr, 0, nullptr, 0},
    };
    Bytes msg = bytesOf("benchmark message");
    bool allOk = true;
    for (const Alg &a : algs) {
        EVP_PKEY *key = a.curve ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", a.curve)
                                : (a.bits ? EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(a.bits))
                                          : EVP_PKEY_Q_keygen(nullptr, nullptr, a.type));
        int pubLen = i2d_PUBKEY(key, nullptr);
        using clk = chrono::steady_clock;
        Bytes sig;
        int nSign = 0, nVer = 0;
        auto t0 = clk::now();
        while (clk::now() - t0 < chrono::milliseconds(150)) {
            sig = evpSign(key, a.md, a.pad, msg);
            ++nSign;
        }
        double tSign = chrono::duration<double>(clk::now() - t0).count();
        t0 = clk::now();
        while (clk::now() - t0 < chrono::milliseconds(150)) {
            allOk &= evpVerify(key, a.md, a.pad, msg, sig);
            ++nVer;
        }
        double tVer = chrono::duration<double>(clk::now() - t0).count();
        printf(" %-20s %8d %8zu %10.0f %10.0f\n", a.name, pubLen, sig.size(),
               nSign / tSign, nVer / tVer);
        EVP_PKEY_free(key);
    }
    check("every signature verified", allOk);
    printf(" (SPKI = DER public-key file size; speeds depend on the CPU)\n\n");
}

int main() {
    Ed E{BN_new(), BN_new(), nullptr, BN_CTX_new()};
    BN_set_word(E.p, 1); BN_lshift(E.p, E.p, 255); BN_sub_word(E.p, 19);
    BIGNUM *t = BN_new();
    BN_set_word(t, 121666);
    BN_mod_inverse(t, t, E.p, E.ctx);
    BN_set_word(E.d, 121665);
    BN_mod_mul(E.d, E.d, t, E.p, E.ctx);
    BN_sub(E.d, E.p, E.d);
    BN_free(t);

    BN_dec2bn(&E.L, "7237005577332262213973186563042994240857116359379907606001950938285454250989");

    Bytes Benc(32, 0x66);
    Benc[0] = 0x58;
    EPt B = newPt(), O = newPt();
    decode(E, Benc, B);
    edMul(E, O, E.L, B);
    check("L * B = identity (0, 1)", BN_is_zero(O.x) && BN_is_one(O.y));
    printf("\n");

    part1And2(E, B);
    part3Compare();

    freePt(B); freePt(O);
    BN_free(E.p); BN_free(E.d); BN_free(E.L); BN_CTX_free(E.ctx);

    printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
