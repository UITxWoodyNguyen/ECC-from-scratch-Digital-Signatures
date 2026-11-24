#include "x25519_edu.h"
#include "ec_math.h"
#include "ec_keys.h"

static void cswap(int swap, BIGNUM *a, BIGNUM *b) {
    if (swap) {
        BN_swap(a, b);
    }
}

Bytes x25519MontgomeryLadder(const Bytes &scalar, const Bytes &uCoord) {
    if (scalar.size() != 32 || uCoord.size() != 32) return {};

    BnCtxPtr ctx = makeBnCtx();
    Bytes kBytes = scalar;
    Bytes uBytes = uCoord;

    kBytes[0] &= 248;
    kBytes[31] &= 127;
    kBytes[31] |= 64;

    uBytes[31] &= 127;

    BnPtr p = makeBn();
    BN_set_word(p.get(), 1);
    BN_lshift(p.get(), p.get(), 255);
    BN_sub_word(p.get(), 19);

    BnPtr k = makeBn();
    BN_lebin2bn(kBytes.data(), 32, k.get());

    BnPtr x1 = makeBn();
    BN_lebin2bn(uBytes.data(), 32, x1.get());
    BN_nnmod(x1.get(), x1.get(), p.get(), ctx.get());

    BnPtr a24 = makeBn();
    BN_set_word(a24.get(), 121665);

    BnPtr x2 = makeBn();
    BnPtr z2 = makeBn();
    BnPtr x3 = makeBn();
    BnPtr z3 = makeBn();

    BN_one(x2.get());
    BN_zero(z2.get());
    BN_copy(x3.get(), x1.get());
    BN_one(z3.get());

    BnPtr A = makeBn();
    BnPtr AA = makeBn();
    BnPtr B = makeBn();
    BnPtr BB = makeBn();
    BnPtr E = makeBn();
    BnPtr C = makeBn();
    BnPtr D = makeBn();
    BnPtr DA = makeBn();
    BnPtr CB = makeBn();
    BnPtr t = makeBn();

    int swap = 0;
    FORD(i, 254, 0) {
        int bit = BN_is_bit_set(k.get(), i);
        swap ^= bit;
        cswap(swap, x2.get(), x3.get());
        cswap(swap, z2.get(), z3.get());
        swap = bit;

        BN_mod_add(A.get(), x2.get(), z2.get(), p.get(), ctx.get());
        BN_mod_sqr(AA.get(), A.get(), p.get(), ctx.get());

        BN_mod_sub(B.get(), x2.get(), z2.get(), p.get(), ctx.get());
        BN_mod_sqr(BB.get(), B.get(), p.get(), ctx.get());

        BN_mod_sub(E.get(), AA.get(), BB.get(), p.get(), ctx.get());

        BN_mod_add(C.get(), x3.get(), z3.get(), p.get(), ctx.get());
        BN_mod_sub(D.get(), x3.get(), z3.get(), p.get(), ctx.get());

        BN_mod_mul(DA.get(), D.get(), A.get(), p.get(), ctx.get());
        BN_mod_mul(CB.get(), C.get(), B.get(), p.get(), ctx.get());

        BN_mod_add(t.get(), DA.get(), CB.get(), p.get(), ctx.get());
        BN_mod_sqr(x3.get(), t.get(), p.get(), ctx.get());

        BN_mod_sub(t.get(), DA.get(), CB.get(), p.get(), ctx.get());
        BN_mod_sqr(t.get(), t.get(), p.get(), ctx.get());
        BN_mod_mul(z3.get(), x1.get(), t.get(), p.get(), ctx.get());

        BN_mod_mul(x2.get(), AA.get(), BB.get(), p.get(), ctx.get());

        BN_mod_mul(t.get(), a24.get(), E.get(), p.get(), ctx.get());
        BN_mod_add(t.get(), AA.get(), t.get(), p.get(), ctx.get());
        BN_mod_mul(z2.get(), E.get(), t.get(), p.get(), ctx.get());
    }
    cswap(swap, x2.get(), x3.get());
    cswap(swap, z2.get(), z3.get());

    BnPtr exp = makeBn();
    BN_copy(exp.get(), p.get());
    BN_sub_word(exp.get(), 2);

    BN_mod_exp(z2.get(), z2.get(), exp.get(), p.get(), ctx.get());
    BN_mod_mul(x2.get(), x2.get(), z2.get(), p.get(), ctx.get());

    Bytes result(32, 0);
    BN_bn2lebinpad(x2.get(), result.data(), 32);

    BN_clear(k.get());
    return result;
}

int handleX25519SelfTest() {
    Bytes aPriv = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    Bytes bPriv = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    Bytes aPubExp = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    Bytes bPubExp = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    Bytes sharedExp = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    Bytes basePoint(32, 0);
    basePoint[0] = 9;

    Bytes aPub = x25519MontgomeryLadder(aPriv, basePoint);
    Bytes bPub = x25519MontgomeryLadder(bPriv, basePoint);

    if (aPub != aPubExp || bPub != bPubExp) {
        cerr << "X25519 public key derivation failed" << endl;
        return RET_CRYPTO;
    }

    Bytes z1 = x25519MontgomeryLadder(aPriv, bPub);
    Bytes z2 = x25519MontgomeryLadder(bPriv, aPub);

    if (z1 != sharedExp || z2 != sharedExp) {
        cerr << "X25519 shared secret derivation failed" << endl;
        return RET_CRYPTO;
    }

    EvpPkeyPtr aKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, aPriv.data(), 32));
    EvpPkeyPtr bKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, bPubExp.data(), 32));
    if (!aKey || !bKey) {
        cerr << "OpenSSL X25519 key creation failed" << endl;
        return RET_INTERNAL;
    }

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new_from_pkey(nullptr, aKey.get(), nullptr));
    if (!dctx || EVP_PKEY_derive_init(dctx.get()) <= 0) {
        cerr << "EVP_PKEY_derive_init failed" << endl;
        return RET_INTERNAL;
    }
    if (EVP_PKEY_derive_set_peer_ex(dctx.get(), bKey.get(), 1) <= 0) {
        cerr << "EVP_PKEY_derive_set_peer_ex failed" << endl;
        return RET_INTERNAL;
    }

    size_t zLen = 0;
    if (EVP_PKEY_derive(dctx.get(), nullptr, &zLen) <= 0 || zLen != 32) {
        cerr << "EVP_PKEY_derive size failed" << endl;
        return RET_INTERNAL;
    }
    Bytes zOssl(zLen);
    if (EVP_PKEY_derive(dctx.get(), zOssl.data(), &zLen) <= 0 || zOssl != sharedExp) {
        cerr << "OpenSSL derived secret mismatch" << endl;
        return RET_CRYPTO;
    }

    Bytes zeroPoint(32, 0);
    Bytes zZero = x25519MontgomeryLadder(aPriv, zeroPoint);
    bool allZero = true;
    for (uint8_t b : zZero) {
        if (b != 0) { allZero = false; break; }
    }
    if (!allZero) {
        cerr << "Low-order point check failed" << endl;
        return RET_CRYPTO;
    }

    string aPubStr = toHex(aPub, false);
    string bPubStr = toHex(bPub, false);
    string zStr = toHex(z1, false);

    cout << "Public keys " << aPubStr.substr(0, 8) << "..." << aPubStr.substr(aPubStr.size() - 4)
         << ", " << bPubStr.substr(0, 8) << "..." << bPubStr.substr(bPubStr.size() - 4)
         << "; shared " << zStr.substr(0, 8) << "..." << zStr.substr(zStr.size() - 4) << endl;

    return RET_OK;
}

int handleEcdhSelfTest(int argc, char **argv) {
    string curveName = "P-256";
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
    }

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    EvpPkeyPtr aliceKey(EVP_EC_gen(curve.name.c_str()));
    EvpPkeyPtr bobKey(EVP_EC_gen(curve.name.c_str()));
    if (!aliceKey || !bobKey) {
        cerr << "Failed to generate key pairs" << endl;
        return RET_INTERNAL;
    }

    BnPtr dA = makeBn();
    BnPtr dB = makeBn();
    BIGNUM *rawDA = dA.get();
    BIGNUM *rawDB = dB.get();
    EVP_PKEY_get_bn_param(aliceKey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &rawDA);
    EVP_PKEY_get_bn_param(bobKey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &rawDB);

    uint8_t aPubBuf[133] = {0};
    uint8_t bPubBuf[133] = {0};
    size_t aPubLen = 0, bPubLen = 0;
    EVP_PKEY_get_octet_string_param(aliceKey.get(), OSSL_PKEY_PARAM_PUB_KEY, aPubBuf, sizeof(aPubBuf), &aPubLen);
    EVP_PKEY_get_octet_string_param(bobKey.get(), OSSL_PKEY_PARAM_PUB_KEY, bPubBuf, sizeof(bPubBuf), &bPubLen);

    EcAffinePoint QA = newAffinePoint();
    EcAffinePoint QB = newAffinePoint();
    string err;
    decodeSec1Point(curve, Bytes(aPubBuf, aPubBuf + aPubLen), QA, err, ctx.get());
    decodeSec1Point(curve, Bytes(bPubBuf, bPubBuf + bPubLen), QB, err, ctx.get());

    EcAffinePoint ZA = newAffinePoint();
    EcAffinePoint ZB = newAffinePoint();
    ecPointMul(curve, ZA, dA.get(), QB, ctx.get());
    ecPointMul(curve, ZB, dB.get(), QA, ctx.get());

    if (ZA.isInf || ZB.isInf || !compareAffinePoints(ZA, ZB)) {
        cout << "FAIL" << endl;
        return RET_CRYPTO;
    }

    size_t fBytes = curve.fieldBytes;
    Bytes zHand(fBytes);
    BN_bn2binpad(ZA.x.get(), zHand.data(), static_cast<int>(fBytes));

    EvpPkeyCtxPtr dctxA(EVP_PKEY_CTX_new_from_pkey(nullptr, aliceKey.get(), nullptr));
    EVP_PKEY_derive_init(dctxA.get());
    EVP_PKEY_derive_set_peer_ex(dctxA.get(), bobKey.get(), 1);
    size_t zLenA = 0;
    EVP_PKEY_derive(dctxA.get(), nullptr, &zLenA);
    Bytes zOsslA(zLenA);
    EVP_PKEY_derive(dctxA.get(), zOsslA.data(), &zLenA);

    EvpPkeyCtxPtr dctxB(EVP_PKEY_CTX_new_from_pkey(nullptr, bobKey.get(), nullptr));
    EVP_PKEY_derive_init(dctxB.get());
    EVP_PKEY_derive_set_peer_ex(dctxB.get(), aliceKey.get(), 1);
    size_t zLenB = 0;
    EVP_PKEY_derive(dctxB.get(), nullptr, &zLenB);
    Bytes zOsslB(zLenB);
    EVP_PKEY_derive(dctxB.get(), zOsslB.data(), &zLenB);

    if (zHand != zOsslA || zHand != zOsslB) {
        cout << "FAIL" << endl;
        return RET_CRYPTO;
    }

    cout << "All PASS" << endl;
    return RET_OK;
}
