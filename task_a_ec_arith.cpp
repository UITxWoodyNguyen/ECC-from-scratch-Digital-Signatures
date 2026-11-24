#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

using namespace std;

#define ll int64_t
#define FOR(i, a, b) for (int i = a, _b = (b); i <= _b; ++i)
#define REP(i, a, b) for (int i = a, _b = (b); i < _b; ++i)
#define FORD(i, b, a) for (int i = (b), _a = (a); i >= _a; --i)
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

struct Curve {
    BIGNUM *p;
    BIGNUM *a;
    BIGNUM *b;
};

struct Pt {
    BIGNUM *x;
    BIGNUM *y;
    bool inf;
};

static Pt newPt() {
    Pt pt{BN_new(), BN_new(), true};
    return pt;
}

static void freePt(Pt &pt) {
    if (pt.x) BN_free(pt.x);
    if (pt.y) BN_free(pt.y);
    pt.x = nullptr;
    pt.y = nullptr;
}

static void copyPt(Pt &dst, const Pt &src) {
    BN_copy(dst.x, src.x);
    BN_copy(dst.y, src.y);
    dst.inf = src.inf;
}

static bool samePt(const Pt &A, const Pt &B) {
    if (A.inf || B.inf) return (A.inf == B.inf);
    return (BN_cmp(A.x, B.x) == 0 && BN_cmp(A.y, B.y) == 0);
}

static bool onCurve(const Curve &E, const Pt &P, BN_CTX *ctx) {
    if (P.inf) return true;
    if (BN_cmp(P.x, E.p) >= 0 || BN_cmp(P.y, E.p) >= 0) return false;

    BIGNUM *lhs = BN_new();
    BIGNUM *rhs = BN_new();
    BIGNUM *term = BN_new();

    BN_mod_sqr(lhs, P.y, E.p, ctx);

    BN_mod_sqr(rhs, P.x, E.p, ctx);
    BN_mod_mul(rhs, rhs, P.x, E.p, ctx);
    BN_mod_mul(term, E.a, P.x, E.p, ctx);
    BN_mod_add(rhs, rhs, term, E.p, ctx);
    BN_mod_add(rhs, rhs, E.b, E.p, ctx);

    bool ok = (BN_cmp(lhs, rhs) == 0);

    BN_free(lhs);
    BN_free(rhs);
    BN_free(term);
    return ok;
}

static void ecAdd(const Curve &E, Pt &R, const Pt &P, const Pt &Q, BN_CTX *ctx) {
    if (P.inf) { copyPt(R, Q); return; }
    if (Q.inf) { copyPt(R, P); return; }

    BIGNUM *num = BN_new();
    BIGNUM *den = BN_new();
    BIGNUM *lam = BN_new();
    BIGNUM *x3 = BN_new();
    BIGNUM *y3 = BN_new();

    if (BN_cmp(P.x, Q.x) == 0) {
        BN_mod_add(num, P.y, Q.y, E.p, ctx);
        if (BN_is_zero(num)) {
            R.inf = true;
            BN_free(num); BN_free(den); BN_free(lam); BN_free(x3); BN_free(y3);
            return;
        }
        BN_mod_sqr(num, P.x, E.p, ctx);
        BN_mul_word(num, 3);
        BN_mod_add(num, num, E.a, E.p, ctx);

        BN_mod_add(den, P.y, P.y, E.p, ctx);
    } else {
        BN_mod_sub(num, Q.y, P.y, E.p, ctx);
        BN_mod_sub(den, Q.x, P.x, E.p, ctx);
    }

    if (!BN_mod_inverse(den, den, E.p, ctx)) {
        R.inf = true;
        BN_free(num); BN_free(den); BN_free(lam); BN_free(x3); BN_free(y3);
        return;
    }
    BN_mod_mul(lam, num, den, E.p, ctx);

    BN_mod_sqr(x3, lam, E.p, ctx);
    BN_mod_sub(x3, x3, P.x, E.p, ctx);
    BN_mod_sub(x3, x3, Q.x, E.p, ctx);

    BN_mod_sub(y3, P.x, x3, E.p, ctx);
    BN_mod_mul(y3, lam, y3, E.p, ctx);
    BN_mod_sub(y3, y3, P.y, E.p, ctx);

    BN_copy(R.x, x3);
    BN_copy(R.y, y3);
    R.inf = false;

    BN_free(num); BN_free(den); BN_free(lam); BN_free(x3); BN_free(y3);
}

static void ecDbl(const Curve &E, Pt &R, const Pt &P, BN_CTX *ctx) {
    ecAdd(E, R, P, P, ctx);
}

static void ecMul(const Curve &E, Pt &R, const BIGNUM *k, const Pt &P, BN_CTX *ctx) {
    if (BN_is_zero(k) || P.inf) {
        R.inf = true;
        return;
    }
    Pt acc = newPt();
    acc.inf = true;
    int numBits = BN_num_bits(k);
    for (int i = numBits - 1; i >= 0; --i) {
        ecDbl(E, acc, acc, ctx);
        if (BN_is_bit_set(k, i)) {
            ecAdd(E, acc, acc, P, ctx);
        }
    }
    copyPt(R, acc);
    freePt(acc);
}

static void fromOpenSSL(const EC_GROUP *g, const EC_POINT *P, Pt &out, BN_CTX *ctx) {
    out.inf = (EC_POINT_is_at_infinity(g, P) == 1);
    if (!out.inf) {
        EC_POINT_get_affine_coordinates(g, P, out.x, out.y, ctx);
    }
}

static EC_POINT *toOpenSSL(const EC_GROUP *g, const Pt &P, BN_CTX *ctx) {
    EC_POINT *R = EC_POINT_new(g);
    if (P.inf) {
        EC_POINT_set_to_infinity(g, R);
    } else {
        EC_POINT_set_affine_coordinates(g, R, P.x, P.y, ctx);
    }
    return R;
}

static bool sameAs(const EC_GROUP *g, const Pt &P, const EC_POINT *Q, BN_CTX *ctx) {
    Pt T = newPt();
    fromOpenSSL(g, Q, T, ctx);
    bool ok = samePt(P, T);
    freePt(T);
    return ok;
}

struct NamedCurve {
    Curve E;
    EC_GROUP *g;
    const BIGNUM *n;
    Pt G;
};

static NamedCurve loadCurve(int nid, BN_CTX *ctx) {
    NamedCurve C;
    C.E.p = BN_new();
    C.E.a = BN_new();
    C.E.b = BN_new();
    C.g = EC_GROUP_new_by_curve_name(nid);
    EC_GROUP_get_curve(C.g, C.E.p, C.E.a, C.E.b, ctx);
    C.n = EC_GROUP_get0_order(C.g);
    C.G = newPt();
    fromOpenSSL(C.g, EC_GROUP_get0_generator(C.g), C.G, ctx);
    return C;
}

static void freeCurve(NamedCurve &C) {
    BN_free(C.E.p);
    BN_free(C.E.a);
    BN_free(C.E.b);
    freePt(C.G);
    EC_GROUP_free(C.g);
}

static void part1GroupLaw(BN_CTX *ctx) {
    printf("== Part 1: group law on NIST P-256 ==\n");
    NamedCurve C = loadCurve(NID_X9_62_prime256v1, ctx);
    printBnBits("p", C.E.p);
    printBnBits("n (order)", C.n);
    printBnBits("G.x", C.G.x);
    check("G is on the curve (our check)", onCurve(C.E, C.G, ctx));

    const EC_POINT *Gs = EC_GROUP_get0_generator(C.g);
    EC_POINT *R = EC_POINT_new(C.g);
    Pt P2 = newPt(), P3 = newPt(), T = newPt(), O = newPt(), negG = newPt();

    ecDbl(C.E, P2, C.G, ctx);
    EC_POINT_dbl(C.g, R, Gs, ctx);
    printBnBits("2G.x", P2.x);
    check("doubling: G + G == EC_POINT_dbl(G)", sameAs(C.g, P2, R, ctx));

    ecAdd(C.E, P3, P2, C.G, ctx);
    EC_POINT *P2s = toOpenSSL(C.g, P2, ctx);
    EC_POINT_add(C.g, R, P2s, Gs, ctx);
    check("addition: 2G + G == EC_POINT_add(2G, G)", sameAs(C.g, P3, R, ctx));

    ecAdd(C.E, T, C.G, O, ctx);
    check("identity: G + O == G", samePt(T, C.G));

    BN_copy(negG.x, C.G.x);
    BN_sub(negG.y, C.E.p, C.G.y);
    negG.inf = false;
    ecAdd(C.E, T, C.G, negG, ctx);
    check("inverse: G + (-G) == O", T.inf);

    BIGNUM *k = BN_new();
    BN_copy(k, C.n);
    BN_sub_word(k, 1);
    ecMul(C.E, T, k, C.G, ctx);
    check("(n-1) G == -G", samePt(T, negG));

    bool same = true;
    Pt acc = newPt();
    acc.inf = true;
    for (int i = 1; i <= 50; ++i) {
        ecAdd(C.E, acc, acc, C.G, ctx);
        BN_set_word(k, i);
        EC_POINT_mul(C.g, R, k, nullptr, nullptr, ctx);
        same &= sameAs(C.g, acc, R, ctx);
    }
    check("iG by repeated addition == EC_POINT_mul, i = 1..50", same);
    printf("\n");

    freePt(P2); freePt(P3); freePt(T); freePt(O); freePt(negG); freePt(acc);
    EC_POINT_free(R); EC_POINT_free(P2s); BN_free(k); freeCurve(C);
}

static void part2Curves(BN_CTX *ctx) {
    printf("== Part 2: double-and-add vs EC_POINT_mul ==\n");
    struct { int nid; const char *name; } curves[] = {
        {NID_X9_62_prime256v1, "P-256"},
        {NID_secp384r1, "P-384"},
        {NID_secp256k1, "secp256k1"}
    };

    for (auto &c : curves) {
        NamedCurve C = loadCurve(c.nid, ctx);
        EC_POINT *R = EC_POINT_new(C.g);
        BIGNUM *k = BN_new();
        Pt M = newPt();

        bool same = true;
        for (int i = 0; i < 10; ++i) {
            BN_rand_range(k, C.n);
            ecMul(C.E, M, k, C.G, ctx);
            EC_POINT_mul(C.g, R, k, nullptr, nullptr, ctx);
            same &= sameAs(C.g, M, R, ctx);
        }
        printf(" %-10s p: %d bits, a = %s\n", c.name, BN_num_bits(C.E.p),
               BN_is_zero(C.E.a) ? "0" : "p - 3");
        check(" 10 random k: double-and-add == EC_POINT_mul", same);

        ecMul(C.E, M, C.n, C.G, ctx);
        check(" n G == O", M.inf);

        BN_copy(k, C.n);
        BN_add_word(k, 1);
        ecMul(C.E, M, k, C.G, ctx);
        check(" (n+1) G == G", samePt(M, C.G));

        freePt(M); BN_free(k); EC_POINT_free(R); freeCurve(C);
    }
    printf("\n");
}

static void part3Validation(BN_CTX *ctx) {
    printf("== Part 3: point validation and encoding (P-256) ==\n");
    NamedCurve C = loadCurve(NID_X9_62_prime256v1, ctx);
    BIGNUM *k = BN_new();
    EC_POINT *Ps = EC_POINT_new(C.g), *Q = EC_POINT_new(C.g);
    BN_rand_range(k, C.n);
    EC_POINT_mul(C.g, Ps, k, nullptr, nullptr, ctx);

    unsigned char unc[65], cmp[33];
    size_t lu = EC_POINT_point2oct(C.g, Ps, POINT_CONVERSION_UNCOMPRESSED, unc, sizeof(unc), ctx);
    size_t lc = EC_POINT_point2oct(C.g, Ps, POINT_CONVERSION_COMPRESSED, cmp, sizeof(cmp), ctx);

    printHex("uncompressed", unc, lu, 20);
    printHex("compressed", cmp, lc, 20);
    check("uncompressed starts with 04, compressed with 02/03",
          unc[0] == 0x04 && (cmp[0] == 0x02 || cmp[0] == 0x03));

    EC_POINT_oct2point(C.g, Q, cmp, lc, ctx);
    check("compressed point decodes to the same point", EC_POINT_cmp(C.g, Q, Ps, ctx) == 0);

    unsigned char bad[65];
    memcpy(bad, unc, 65);
    bad[64] ^= 0x01;
    check("off-curve point is rejected by EC_POINT_oct2point",
          EC_POINT_oct2point(C.g, Q, bad, 65, ctx) != 1);
    ERR_clear_error();

    Curve E2{C.E.p, C.E.a, BN_new()};
    BN_copy(E2.b, C.E.b);
    BN_add_word(E2.b, 1);
    Pt A = newPt();
    BIGNUM *rhs = BN_new(), *t = BN_new();

    for (unsigned long x = 1;; ++x) {
        BN_set_word(A.x, x);
        BN_mod_sqr(rhs, A.x, E2.p, ctx);
        BN_mod_mul(rhs, rhs, A.x, E2.p, ctx);
        BN_mod_mul(t, E2.a, A.x, E2.p, ctx);
        BN_mod_add(rhs, rhs, t, E2.p, ctx);
        BN_mod_add(rhs, rhs, E2.b, E2.p, ctx);
        if (BN_mod_sqrt(A.y, rhs, E2.p, ctx)) break;
        ERR_clear_error();
    }
    A.inf = false;
    check("attacker's point is NOT on P-256", !onCurve(C.E, A, ctx));
    check("... but it is on the curve with b' = b + 1", onCurve(E2, A, ctx));

    EC_GROUP *g2 = EC_GROUP_new_curve_GFp(E2.p, E2.a, E2.b, ctx);
    EC_POINT *A2 = toOpenSSL(g2, A, ctx), *R2 = EC_POINT_new(g2);
    Pt M = newPt();

    ecMul(C.E, M, k, A, ctx);
    EC_POINT_mul(g2, R2, nullptr, A2, k, ctx);
    check("our P-256 ecMul silently computes k*A on the other curve", sameAs(g2, M, R2, ctx));

    unsigned char enc[65];
    enc[0] = 0x04;
    BN_bn2binpad(A.x, enc + 1, 32);
    BN_bn2binpad(A.y, enc + 33, 32);
    check("EC_POINT_oct2point on P-256 rejects it", EC_POINT_oct2point(C.g, Q, enc, 65, ctx) != 1);
    ERR_clear_error();

    printf("  -> without the on-curve check, k * (attacker point) leaks k modulo small factors\n");
    printf("     of the other curve's order (invalid-curve attack)\n\n");

    freePt(A); freePt(M); BN_free(E2.b); BN_free(rhs); BN_free(t); BN_clear_free(k);
    EC_POINT_free(Ps); EC_POINT_free(Q); EC_POINT_free(A2); EC_POINT_free(R2);
    EC_GROUP_free(g2); freeCurve(C);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    part1GroupLaw(ctx);
    part2Curves(ctx);
    part3Validation(ctx);
    BN_CTX_free(ctx);

    printf("%s\n", g_failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return g_failures ? 1 : 0;
}
