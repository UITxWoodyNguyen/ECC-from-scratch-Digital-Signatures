#include "ec_math.h"

bool loadNamedCurve(const string &name, EcCurve &curve, BN_CTX *ctx) {
    int nid = NID_undef;
    if (name == "P-256" || name == "prime256v1" || name == "secp256r1") {
        nid = NID_X9_62_prime256v1;
        curve.name = "P-256";
    } else if (name == "P-384" || name == "secp384r1") {
        nid = NID_secp384r1;
        curve.name = "P-384";
    } else if (name == "secp256k1") {
        nid = NID_secp256k1;
        curve.name = "secp256k1";
    } else {
        nid = OBJ_txt2nid(name.c_str());
        if (nid == NID_undef) return false;
        curve.name = name;
    }

    curve.nid = nid;
    EC_GROUP *rawGrp = EC_GROUP_new_by_curve_name(nid);
    if (!rawGrp) return false;
    curve.grp.reset(rawGrp);

    curve.p = makeBn();
    curve.a = makeBn();
    curve.b = makeBn();
    if (EC_GROUP_get_curve(curve.grp.get(), curve.p.get(), curve.a.get(), curve.b.get(), ctx) != 1) {
        return false;
    }

    const BIGNUM *orderBn = EC_GROUP_get0_order(curve.grp.get());
    if (!orderBn) return false;
    curve.n = makeBn();
    BN_copy(curve.n.get(), orderBn);

    curve.fieldBytes = static_cast<size_t>((BN_num_bits(curve.p.get()) + 7) / 8);

    const EC_POINT *rawG = EC_GROUP_get0_generator(curve.grp.get());
    if (!rawG) return false;
    EC_POINT *gCopy = EC_POINT_dup(rawG, curve.grp.get());
    if (!gCopy) return false;
    curve.G.reset(gCopy);

    return true;
}

EcAffinePoint newAffinePoint() {
    EcAffinePoint pt;
    pt.x = makeBn();
    pt.y = makeBn();
    pt.isInf = true;
    return pt;
}

EcAffinePoint copyAffinePoint(const EcAffinePoint &pt) {
    EcAffinePoint copy;
    copy.x = makeBn();
    copy.y = makeBn();
    if (pt.x) BN_copy(copy.x.get(), pt.x.get());
    if (pt.y) BN_copy(copy.y.get(), pt.y.get());
    copy.isInf = pt.isInf;
    return copy;
}

bool isPointOnCurve(const EcCurve &curve, const EcAffinePoint &pt, BN_CTX *ctx) {
    if (pt.isInf) return true;
    if (BN_cmp(pt.x.get(), curve.p.get()) >= 0 || BN_cmp(pt.y.get(), curve.p.get()) >= 0) return false;

    BnPtr lhs = makeBn();
    BnPtr rhs = makeBn();
    BnPtr term = makeBn();

    BN_mod_sqr(lhs.get(), pt.y.get(), curve.p.get(), ctx);

    BN_mod_sqr(rhs.get(), pt.x.get(), curve.p.get(), ctx);
    BN_mod_mul(rhs.get(), rhs.get(), pt.x.get(), curve.p.get(), ctx);
    BN_mod_mul(term.get(), curve.a.get(), pt.x.get(), curve.p.get(), ctx);
    BN_mod_add(rhs.get(), rhs.get(), term.get(), curve.p.get(), ctx);
    BN_mod_add(rhs.get(), rhs.get(), curve.b.get(), curve.p.get(), ctx);

    return (BN_cmp(lhs.get(), rhs.get()) == 0);
}

void ecPointAdd(const EcCurve &curve, EcAffinePoint &res, const EcAffinePoint &P, const EcAffinePoint &Q, BN_CTX *ctx) {
    if (P.isInf) {
        res = copyAffinePoint(Q);
        return;
    }
    if (Q.isInf) {
        res = copyAffinePoint(P);
        return;
    }

    BnPtr num = makeBn();
    BnPtr den = makeBn();
    BnPtr lambda = makeBn();
    BnPtr x3 = makeBn();
    BnPtr y3 = makeBn();

    if (BN_cmp(P.x.get(), Q.x.get()) == 0) {
        BN_mod_add(num.get(), P.y.get(), Q.y.get(), curve.p.get(), ctx);
        if (BN_is_zero(num.get())) {
            res.isInf = true;
            return;
        }
        BN_mod_sqr(num.get(), P.x.get(), curve.p.get(), ctx);
        BN_mul_word(num.get(), 3);
        BN_mod_add(num.get(), num.get(), curve.a.get(), curve.p.get(), ctx);

        BN_mod_add(den.get(), P.y.get(), P.y.get(), curve.p.get(), ctx);
    } else {
        BN_mod_sub(num.get(), Q.y.get(), P.y.get(), curve.p.get(), ctx);
        BN_mod_sub(den.get(), Q.x.get(), P.x.get(), curve.p.get(), ctx);
    }

    if (!BN_mod_inverse(den.get(), den.get(), curve.p.get(), ctx)) {
        res.isInf = true;
        return;
    }
    BN_mod_mul(lambda.get(), num.get(), den.get(), curve.p.get(), ctx);

    BN_mod_sqr(x3.get(), lambda.get(), curve.p.get(), ctx);
    BN_mod_sub(x3.get(), x3.get(), P.x.get(), curve.p.get(), ctx);
    BN_mod_sub(x3.get(), x3.get(), Q.x.get(), curve.p.get(), ctx);

    BN_mod_sub(y3.get(), P.x.get(), x3.get(), curve.p.get(), ctx);
    BN_mod_mul(y3.get(), lambda.get(), y3.get(), curve.p.get(), ctx);
    BN_mod_sub(y3.get(), y3.get(), P.y.get(), curve.p.get(), ctx);

    BN_copy(res.x.get(), x3.get());
    BN_copy(res.y.get(), y3.get());
    res.isInf = false;
}

void ecPointDbl(const EcCurve &curve, EcAffinePoint &res, const EcAffinePoint &P, BN_CTX *ctx) {
    ecPointAdd(curve, res, P, P, ctx);
}

void ecPointMul(const EcCurve &curve, EcAffinePoint &res, const BIGNUM *k, const EcAffinePoint &P, BN_CTX *ctx) {
    if (BN_is_zero(k) || P.isInf) {
        res.isInf = true;
        return;
    }

    EcAffinePoint acc = newAffinePoint();
    acc.isInf = true;

    int totalBits = BN_num_bits(k);
    for (int i = totalBits - 1; i >= 0; --i) {
        ecPointDbl(curve, acc, acc, ctx);
        if (BN_is_bit_set(k, i)) {
            ecPointAdd(curve, acc, acc, P, ctx);
        }
    }
    res = copyAffinePoint(acc);
}

bool decodeSec1Point(const EcCurve &curve, const Bytes &sec1, EcAffinePoint &pt, string &errReason, BN_CTX *ctx) {
    pt.isInf = true;
    if (sec1.empty()) {
        errReason = "empty encoding";
        return false;
    }
    if (sec1.size() == 1 && sec1[0] == 0x00) {
        pt.isInf = true;
        return true;
    }

    uint8_t prefix = sec1[0];
    size_t fBytes = curve.fieldBytes;

    if (prefix == 0x04) {
        if (sec1.size() != 1 + 2 * fBytes) {
            errReason = "wrong length for uncompressed point";
            return false;
        }
        pt.x = makeBn();
        pt.y = makeBn();
        BN_bin2bn(sec1.data() + 1, static_cast<int>(fBytes), pt.x.get());
        BN_bin2bn(sec1.data() + 1 + fBytes, static_cast<int>(fBytes), pt.y.get());
        pt.isInf = false;

        if (BN_cmp(pt.x.get(), curve.p.get()) >= 0 || BN_cmp(pt.y.get(), curve.p.get()) >= 0) {
            errReason = "coordinate out of range";
            return false;
        }
        if (!isPointOnCurve(curve, pt, ctx)) {
            errReason = "not on curve";
            return false;
        }
        return true;
    } else if (prefix == 0x02 || prefix == 0x03) {
        if (sec1.size() != 1 + fBytes) {
            errReason = "wrong length for compressed point";
            return false;
        }
        pt.x = makeBn();
        pt.y = makeBn();
        BN_bin2bn(sec1.data() + 1, static_cast<int>(fBytes), pt.x.get());
        pt.isInf = false;

        if (BN_cmp(pt.x.get(), curve.p.get()) >= 0) {
            errReason = "coordinate out of range";
            return false;
        }

        BnPtr rhs = makeBn();
        BnPtr term = makeBn();
        BN_mod_sqr(rhs.get(), pt.x.get(), curve.p.get(), ctx);
        BN_mod_mul(rhs.get(), rhs.get(), pt.x.get(), curve.p.get(), ctx);
        BN_mod_mul(term.get(), curve.a.get(), pt.x.get(), curve.p.get(), ctx);
        BN_mod_add(rhs.get(), rhs.get(), term.get(), curve.p.get(), ctx);
        BN_mod_add(rhs.get(), rhs.get(), curve.b.get(), curve.p.get(), ctx);

        if (!BN_mod_sqrt(pt.y.get(), rhs.get(), curve.p.get(), ctx)) {
            errReason = "not on curve";
            return false;
        }

        BnPtr verifyTerm = makeBn();
        BN_mod_sqr(verifyTerm.get(), pt.y.get(), curve.p.get(), ctx);
        if (BN_cmp(verifyTerm.get(), rhs.get()) != 0) {
            errReason = "not on curve";
            return false;
        }

        int targetParity = (prefix == 0x03) ? 1 : 0;
        int currentParity = BN_is_odd(pt.y.get()) ? 1 : 0;
        if (currentParity != targetParity) {
            BN_sub(pt.y.get(), curve.p.get(), pt.y.get());
        }
        return true;
    }

    errReason = "invalid prefix";
    return false;
}

Bytes encodeSec1Point(const EcCurve &curve, const EcAffinePoint &pt, bool compressed, BN_CTX *ctx) {
    (void)ctx;
    if (pt.isInf) {
        return {0x00};
    }
    size_t fBytes = curve.fieldBytes;
    if (compressed) {
        Bytes out(1 + fBytes);
        out[0] = BN_is_odd(pt.y.get()) ? 0x03 : 0x02;
        BN_bn2binpad(pt.x.get(), out.data() + 1, static_cast<int>(fBytes));
        return out;
    } else {
        Bytes out(1 + 2 * fBytes);
        out[0] = 0x04;
        BN_bn2binpad(pt.x.get(), out.data() + 1, static_cast<int>(fBytes));
        BN_bn2binpad(pt.y.get(), out.data() + 1 + fBytes, static_cast<int>(fBytes));
        return out;
    }
}

EcAffinePoint fromOpenSslPoint(const EC_GROUP *grp, const EC_POINT *pt, BN_CTX *ctx) {
    EcAffinePoint res = newAffinePoint();
    if (EC_POINT_is_at_infinity(grp, pt) == 1) {
        res.isInf = true;
        return res;
    }
    res.isInf = false;
    EC_POINT_get_affine_coordinates(grp, pt, res.x.get(), res.y.get(), ctx);
    return res;
}

EC_POINT *toOpenSslPoint(const EC_GROUP *grp, const EcAffinePoint &pt, BN_CTX *ctx) {
    EC_POINT *out = EC_POINT_new(grp);
    if (!out) return nullptr;
    if (pt.isInf) {
        EC_POINT_set_to_infinity(grp, out);
    } else {
        EC_POINT_set_affine_coordinates(grp, out, pt.x.get(), pt.y.get(), ctx);
    }
    return out;
}

bool compareAffinePoints(const EcAffinePoint &P1, const EcAffinePoint &P2) {
    if (P1.isInf || P2.isInf) return (P1.isInf == P2.isInf);
    return (BN_cmp(P1.x.get(), P2.x.get()) == 0 && BN_cmp(P1.y.get(), P2.y.get()) == 0);
}

// Handlers for CLI Task A
int handleEcAdd(int argc, char **argv) {
    string curveName = "P-256";
    string pHex, qHex;
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if (arg == "-P" && i + 1 < argc) pHex = argv[++i];
        else if (arg == "-Q" && i + 1 < argc) qHex = argv[++i];
    }
    if (pHex.empty() || qHex.empty()) {
        cerr << "Usage: lab03 ec-add --curve <c> -P <hex> -Q <hex>" << endl;
        return RET_USAGE;
    }

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    Bytes pBytes = fromHex(pHex);
    Bytes qBytes = fromHex(qHex);
    EcAffinePoint P = newAffinePoint();
    EcAffinePoint Q = newAffinePoint();
    string reason;
    if (!decodeSec1Point(curve, pBytes, P, reason, ctx.get())) {
        cerr << "Invalid point P: " << reason << endl;
        return RET_DATA;
    }
    if (!decodeSec1Point(curve, qBytes, Q, reason, ctx.get())) {
        cerr << "Invalid point Q: " << reason << endl;
        return RET_DATA;
    }

    EcAffinePoint R = newAffinePoint();
    ecPointAdd(curve, R, P, Q, ctx.get());
    Bytes enc = encodeSec1Point(curve, R, false, ctx.get());
    cout << toHex(enc, true) << endl;
    return RET_OK;
}

int handleEcDbl(int argc, char **argv) {
    string curveName = "P-256";
    string pHex;
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if (arg == "-P" && i + 1 < argc) pHex = argv[++i];
    }
    if (pHex.empty()) {
        cerr << "Usage: lab03 ec-dbl --curve <c> -P <hex>" << endl;
        return RET_USAGE;
    }

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    Bytes pBytes = fromHex(pHex);
    EcAffinePoint P = newAffinePoint();
    string reason;
    if (!decodeSec1Point(curve, pBytes, P, reason, ctx.get())) {
        cerr << "Invalid point P: " << reason << endl;
        return RET_DATA;
    }

    EcAffinePoint R = newAffinePoint();
    ecPointDbl(curve, R, P, ctx.get());
    Bytes enc = encodeSec1Point(curve, R, false, ctx.get());
    cout << toHex(enc, true) << endl;
    return RET_OK;
}

int handleEcMul(int argc, char **argv) {
    string curveName = "P-256";
    string kStr;
    string pHex;
    bool checkMode = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if (arg == "-k" && i + 1 < argc) kStr = argv[++i];
        else if (arg == "-P" && i + 1 < argc) pHex = argv[++i];
        else if (arg == "--check" || arg == "-check") checkMode = true;
    }
    if (kStr.empty()) {
        cerr << "Usage: lab03 ec-mul --curve <c> -k <decimal> [-P <hex>] [--check]" << endl;
        return RET_USAGE;
    }

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    BnPtr k = makeBn();
    BIGNUM *rawK = k.get();
    if (BN_dec2bn(&rawK, kStr.c_str()) == 0) {
        cerr << "Invalid decimal integer k: " << kStr << endl;
        return RET_USAGE;
    }

    EcAffinePoint P = newAffinePoint();
    if (!pHex.empty()) {
        Bytes pBytes = fromHex(pHex);
        string reason;
        if (!decodeSec1Point(curve, pBytes, P, reason, ctx.get())) {
            cerr << "Invalid point P: " << reason << endl;
            return RET_DATA;
        }
    } else {
        P = fromOpenSslPoint(curve.grp.get(), curve.G.get(), ctx.get());
    }

    EcAffinePoint R = newAffinePoint();
    ecPointMul(curve, R, k.get(), P, ctx.get());

    if (checkMode) {
        EcPointPtr rOssl(EC_POINT_new(curve.grp.get()));
        EcPointPtr pOssl(toOpenSslPoint(curve.grp.get(), P, ctx.get()));
        EC_POINT_mul(curve.grp.get(), rOssl.get(), nullptr, pOssl.get(), k.get(), ctx.get());

        EcAffinePoint rOsslPt = fromOpenSslPoint(curve.grp.get(), rOssl.get(), ctx.get());
        if (compareAffinePoints(R, rOsslPt)) {
            cout << "MATCH" << endl;
        } else {
            cout << "MISMATCH" << endl;
        }
        return RET_OK;
    }

    Bytes enc = encodeSec1Point(curve, R, false, ctx.get());
    cout << toHex(enc, true) << endl;
    return RET_OK;
}

int handleEcValidate(int argc, char **argv) {
    string curveName = "P-256";
    string pointHex;
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if ((arg == "--point" || arg == "-point") && i + 1 < argc) pointHex = argv[++i];
    }
    if (pointHex.empty()) {
        cerr << "Usage: lab03 ec-validate --curve <name> -point <hex>" << endl;
        return RET_USAGE;
    }

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    Bytes ptBytes;
    if (!fromHex(pointHex, ptBytes) || ptBytes.empty()) {
        cout << "reason: invalid hex encoding" << endl;
        return RET_DATA;
    }

    if (ptBytes.size() == 1 && ptBytes[0] == 0x00) {
        cout << "reason: identity point not allowed for public point" << endl;
        return RET_DATA;
    }

    EcAffinePoint pt = newAffinePoint();
    string errReason;
    if (!decodeSec1Point(curve, ptBytes, pt, errReason, ctx.get())) {
        cout << "reason: " << errReason << endl;
        return RET_DATA;
    }

    if (pt.isInf) {
        cout << "reason: identity point not allowed" << endl;
        return RET_DATA;
    }

    cout << "VALID" << endl;
    return RET_OK;
}

int handleEcEncode(int argc, char **argv) {
    string curveName = "P-256";
    string pointHex;
    string formStr = "uncompressed";
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if ((arg == "--point" || arg == "-point") && i + 1 < argc) pointHex = argv[++i];
        else if ((arg == "--form" || arg == "-form") && i + 1 < argc) formStr = argv[++i];
    }
    if (pointHex.empty()) {
        cerr << "Usage: lab03 ec-encode --curve <name> -point <hex> -form <f>" << endl;
        return RET_USAGE;
    }

    bool compressed = (formStr == "compressed");

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    Bytes ptBytes = fromHex(pointHex);
    EcAffinePoint pt = newAffinePoint();
    string reason;
    if (!decodeSec1Point(curve, ptBytes, pt, reason, ctx.get())) {
        cerr << "Invalid point: " << reason << endl;
        return RET_DATA;
    }

    Bytes res = encodeSec1Point(curve, pt, compressed, ctx.get());
    cout << toHex(res, false) << endl;
    return RET_OK;
}

int handleEcInvalidCurveDemo() {
    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve("P-256", curve, ctx.get())) {
        cerr << "Failed to load P-256" << endl;
        return RET_INTERNAL;
    }

    BnPtr bPrime = makeBn();
    BN_copy(bPrime.get(), curve.b.get());
    BN_add_word(bPrime.get(), 1);

    EcAffinePoint A = newAffinePoint();
    A.isInf = false;
    BnPtr rhs = makeBn();
    BnPtr term = makeBn();

    for (unsigned long xVal = 1;; ++xVal) {
        BN_set_word(A.x.get(), xVal);
        BN_mod_sqr(rhs.get(), A.x.get(), curve.p.get(), ctx.get());
        BN_mod_mul(rhs.get(), rhs.get(), A.x.get(), curve.p.get(), ctx.get());
        BN_mod_mul(term.get(), curve.a.get(), A.x.get(), curve.p.get(), ctx.get());
        BN_mod_add(rhs.get(), rhs.get(), term.get(), curve.p.get(), ctx.get());
        BN_mod_add(rhs.get(), rhs.get(), bPrime.get(), curve.p.get(), ctx.get());

        if (BN_mod_sqrt(A.y.get(), rhs.get(), curve.p.get(), ctx.get()) != nullptr) {
            BnPtr sq = makeBn();
            BN_mod_sqr(sq.get(), A.y.get(), curve.p.get(), ctx.get());
            if (BN_cmp(sq.get(), rhs.get()) == 0) break;
        }
        ERR_clear_error();
    }

    bool onRealCurve = isPointOnCurve(curve, A, ctx.get());
    if (onRealCurve) {
        cerr << "Error: constructed point should not be on P-256" << endl;
        return RET_INTERNAL;
    }

    EcGroupPtr gAttacker(EC_GROUP_new_curve_GFp(curve.p.get(), curve.a.get(), bPrime.get(), ctx.get()));
    if (!gAttacker) {
        cerr << "Failed to construct attacker curve" << endl;
        return RET_INTERNAL;
    }

    EcPointPtr aAttacker(EC_POINT_new(gAttacker.get()));
    EC_POINT_set_affine_coordinates(gAttacker.get(), aAttacker.get(), A.x.get(), A.y.get(), ctx.get());

    BnPtr k = makeBn();
    BN_rand_range(k.get(), curve.n.get());

    EcAffinePoint M = newAffinePoint();
    ecPointMul(curve, M, k.get(), A, ctx.get());

    EcPointPtr rAttacker(EC_POINT_new(gAttacker.get()));
    EC_POINT_mul(gAttacker.get(), rAttacker.get(), nullptr, aAttacker.get(), k.get(), ctx.get());

    EcAffinePoint mAttacker = fromOpenSslPoint(gAttacker.get(), rAttacker.get(), ctx.get());
    if (!compareAffinePoints(M, mAttacker)) {
        cerr << "Error in hand-written point multiplication on invalid curve" << endl;
        return RET_INTERNAL;
    }

    Bytes enc = encodeSec1Point(curve, A, false, ctx.get());
    EcPointPtr qVerify(EC_POINT_new(curve.grp.get()));
    if (EC_POINT_oct2point(curve.grp.get(), qVerify.get(), enc.data(), enc.size(), ctx.get()) == 1) {
        cerr << "Error: OpenSSL accepted invalid curve point" << endl;
        return RET_INTERNAL;
    }
    ERR_clear_error();

    string errReason;
    EcAffinePoint testPt = newAffinePoint();
    bool valRes = decodeSec1Point(curve, enc, testPt, errReason, ctx.get());
    if (valRes) {
        cerr << "Error: our ec-validate accepted invalid curve point" << endl;
        return RET_INTERNAL;
    }

    cout << "All checks PASS; the point is rejected by ec-validate" << endl;
    return RET_OK;
}
