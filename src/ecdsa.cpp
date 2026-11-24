#include "ecdsa.h"
#include "sigfile.h"
#include "ec_keys.h"

BnPtr ecdsaBits2Int(const EcCurve &curve, const Bytes &hash) {
    BnPtr e = makeBn();
    BN_bin2bn(hash.data(), static_cast<int>(hash.size()), e.get());
    int extra = static_cast<int>(hash.size() * 8) - BN_num_bits(curve.n.get());
    if (extra > 0) {
        BN_rshift(e.get(), e.get(), extra);
    }
    return e;
}

void ecdsaSignByHand(const EcCurve &curve, const BIGNUM *d, const Bytes &hash,
                     const BIGNUM *k, BIGNUM *r, BIGNUM *s, BN_CTX *ctx) {
    BnPtr e = ecdsaBits2Int(curve, hash);
    EcPointPtr R(EC_POINT_new(curve.grp.get()));
    EC_POINT_mul(curve.grp.get(), R.get(), k, nullptr, nullptr, ctx);

    BnPtr x1 = makeBn();
    EC_POINT_get_affine_coordinates(curve.grp.get(), R.get(), x1.get(), nullptr, ctx);
    BN_nnmod(r, x1.get(), curve.n.get(), ctx);

    BnPtr kinv = makeBn();
    BN_mod_inverse(kinv.get(), k, curve.n.get(), ctx);

    BnPtr t = makeBn();
    BN_mod_mul(t.get(), r, d, curve.n.get(), ctx);
    BN_mod_add(t.get(), t.get(), e.get(), curve.n.get(), ctx);
    BN_mod_mul(s, kinv.get(), t.get(), curve.n.get(), ctx);
}

bool ecdsaVerifyByHand(const EcCurve &curve, const EC_POINT *Q, const Bytes &hash,
                       const BIGNUM *r, const BIGNUM *s, BN_CTX *ctx) {
    if (BN_is_zero(r) || BN_is_zero(s) || BN_is_negative(r) || BN_is_negative(s) ||
        BN_cmp(r, curve.n.get()) >= 0 || BN_cmp(s, curve.n.get()) >= 0) {
        return false;
    }

    BnPtr e = ecdsaBits2Int(curve, hash);
    BnPtr w = makeBn();
    if (!BN_mod_inverse(w.get(), s, curve.n.get(), ctx)) return false;

    BnPtr u1 = makeBn();
    BnPtr u2 = makeBn();
    BN_mod_mul(u1.get(), e.get(), w.get(), curve.n.get(), ctx);
    BN_mod_mul(u2.get(), r, w.get(), curve.n.get(), ctx);

    EcPointPtr X(EC_POINT_new(curve.grp.get()));
    EC_POINT_mul(curve.grp.get(), X.get(), u1.get(), Q, u2.get(), ctx);

    if (EC_POINT_is_at_infinity(curve.grp.get(), X.get()) == 1) return false;

    BnPtr x = makeBn();
    EC_POINT_get_affine_coordinates(curve.grp.get(), X.get(), x.get(), nullptr, ctx);
    BN_nnmod(x.get(), x.get(), curve.n.get(), ctx);

    return (BN_cmp(x.get(), r) == 0);
}

static Bytes hmacSha256(const Bytes &key, const Bytes &data) {
    Bytes out(32);
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &len);
    return out;
}

static Bytes concatBytes(initializer_list<Bytes> list) {
    Bytes res;
    for (const Bytes &b : list) {
        res.insert(res.end(), all(b));
    }
    return res;
}

BnPtr rfc6979Nonce(const EcCurve &curve, const BIGNUM *d, const Bytes &hash) {
    size_t qLen = static_cast<size_t>((BN_num_bits(curve.n.get()) + 7) / 8);
    Bytes x(qLen, 0);
    BN_bn2binpad(d, x.data(), static_cast<int>(qLen));

    BnCtxPtr ctx = makeBnCtx();
    BnPtr e = ecdsaBits2Int(curve, hash);
    BN_nnmod(e.get(), e.get(), curve.n.get(), ctx.get());

    Bytes hb(qLen, 0);
    BN_bn2binpad(e.get(), hb.data(), static_cast<int>(qLen));

    Bytes V(32, 0x01);
    Bytes K(32, 0x00);

    K = hmacSha256(K, concatBytes({V, {0x00}, x, hb}));
    V = hmacSha256(K, V);
    K = hmacSha256(K, concatBytes({V, {0x01}, x, hb}));
    V = hmacSha256(K, V);

    while (true) {
        V = hmacSha256(K, V);
        BnPtr k = ecdsaBits2Int(curve, V);
        if (!BN_is_zero(k.get()) && BN_cmp(k.get(), curve.n.get()) < 0) {
            secureCleanse(x);
            return k;
        }
        K = hmacSha256(K, concatBytes({V, {0x00}}));
        V = hmacSha256(K, V);
    }
}

Bytes encodeEcdsaDer(const BIGNUM *r, const BIGNUM *s) {
    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!sig) return {};
    ECDSA_SIG_set0(sig.get(), BN_dup(r), BN_dup(s));
    uint8_t *der = nullptr;
    int len = i2d_ECDSA_SIG(sig.get(), &der);
    if (len <= 0 || !der) return {};
    Bytes out(der, der + len);
    OPENSSL_free(der);
    return out;
}

bool decodeEcdsaDer(const Bytes &der, BIGNUM *r, BIGNUM *s) {
    const uint8_t *p = der.data();
    EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size())));
    if (!sig) return false;

    const BIGNUM *rSig = ECDSA_SIG_get0_r(sig.get());
    const BIGNUM *sSig = ECDSA_SIG_get0_s(sig.get());
    if (!rSig || !sSig) return false;

    BN_copy(r, rSig);
    BN_copy(s, sSig);
    return true;
}

bool ecdsaEvpSign(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, Bytes &outDerSig) {
    const EVP_MD *md = (algId == ALG_ECDSA_P384_SHA384) ? EVP_sha384() : EVP_sha256();

    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestSignInit(mctx.get(), nullptr, md, nullptr, key) != 1) return false;

    size_t sigLen = 0;
    if (EVP_DigestSign(mctx.get(), nullptr, &sigLen, tbs.data(), tbs.size()) != 1) return false;
    Bytes rawSig(sigLen);
    if (EVP_DigestSign(mctx.get(), rawSig.data(), &sigLen, tbs.data(), tbs.size()) != 1) return false;
    rawSig.resize(sigLen);

    BnPtr r = makeBn();
    BnPtr s = makeBn();
    if (!decodeEcdsaDer(rawSig, r.get(), s.get())) return false;

    string curveName;
    if (algId == ALG_ECDSA_P256_SHA256) curveName = "P-256";
    else if (algId == ALG_ECDSA_P384_SHA384) curveName = "P-384";
    else if (algId == ALG_ECDSA_SECP256K1_SHA256) curveName = "secp256k1";

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) return false;

    BnPtr halfN = makeBn();
    BN_rshift1(halfN.get(), curve.n.get());

    if (BN_cmp(s.get(), halfN.get()) > 0) {
        BN_sub(s.get(), curve.n.get(), s.get());
    }

    outDerSig = encodeEcdsaDer(r.get(), s.get());
    return !outDerSig.empty();
}

bool ecdsaEvpVerify(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, const Bytes &derSig, bool strict, string &warnOrErr) {
    BnPtr r = makeBn();
    BnPtr s = makeBn();
    if (!decodeEcdsaDer(derSig, r.get(), s.get())) {
        warnOrErr = "INVALID: failed to parse DER signature";
        return false;
    }

    Bytes reEncoded = encodeEcdsaDer(r.get(), s.get());
    if (reEncoded != derSig) {
        warnOrErr = "INVALID: non-canonical DER signature";
        return false;
    }

    string curveName;
    if (algId == ALG_ECDSA_P256_SHA256) curveName = "P-256";
    else if (algId == ALG_ECDSA_P384_SHA384) curveName = "P-384";
    else if (algId == ALG_ECDSA_SECP256K1_SHA256) curveName = "secp256k1";

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) return false;

    if (BN_is_zero(r.get()) || BN_is_zero(s.get()) ||
        BN_cmp(r.get(), curve.n.get()) >= 0 || BN_cmp(s.get(), curve.n.get()) >= 0) {
        warnOrErr = "INVALID: r or s out of bounds [1, n-1]";
        return false;
    }

    BnPtr halfN = makeBn();
    BN_rshift1(halfN.get(), curve.n.get());

    if (BN_cmp(s.get(), halfN.get()) > 0) {
        if (strict) {
            warnOrErr = "INVALID: high-s signature in strict mode";
            return false;
        } else {
            warnOrErr = "warning: high-s signature accepted";
        }
    }

    const EVP_MD *md = (algId == ALG_ECDSA_P384_SHA384) ? EVP_sha384() : EVP_sha256();
    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestVerifyInit(mctx.get(), nullptr, md, nullptr, key) != 1) return false;

    int res = EVP_DigestVerify(mctx.get(), derSig.data(), derSig.size(), tbs.data(), tbs.size());
    if (res != 1) {
        ERR_clear_error();
        return false;
    }
    return true;
}

int handleEcdsaDemo(int argc, char **argv) {
    string curveName = "P-256";
    string emitDir;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if ((arg == "--emit-reused" || arg == "-emit-reused") && i + 1 < argc) emitDir = argv[++i];
    }

    if (!emitDir.empty()) {
        createDirectories(emitDir);
        cout << "============================================================" << endl;
        cout << "WARNING: INSECURE NONCE REUSE DEMONSTRATION" << endl;
        cout << "============================================================" << endl;

        EvpPkeyPtr key;
        generateKeyPair("P-256", key);

        string pubPath = emitDir + "/pub.pem";
        BioPtr pubBio(BIO_new_file(pubPath.c_str(), "wb"));
        PEM_write_bio_PUBKEY(pubBio.get(), key.get());

        string m1Path = emitDir + "/msg1.txt";
        string m2Path = emitDir + "/msg2.txt";
        string s1Path = emitDir + "/sig1.sig";
        string s2Path = emitDir + "/sig2.sig";

        string t1 = "Message one: Transfer 10 BTC to Bob";
        string t2 = "Message two: Transfer 50 BTC to Charlie";
        writeFileBytes(m1Path, Bytes(t1.begin(), t1.end()), true);
        writeFileBytes(m2Path, Bytes(t2.begin(), t2.end()), true);

        BnCtxPtr ctx = makeBnCtx();
        EcCurve curve;
        loadNamedCurve("P-256", curve, ctx.get());

        BnPtr d = makeBn();
        BIGNUM *rawD = d.get();
        EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_PRIV_KEY, &rawD);

        BnPtr k = makeBn();
        do {
            BN_rand_range(k.get(), curve.n.get());
        } while (BN_is_zero(k.get()));

        Bytes keyId = computeSpkiKeyId(key.get());

        bool ok = false;
        Bytes h1 = sha512StreamFile(m1Path, ok);
        Bytes tbs1 = buildL3sgTbs(0x01, ALG_ECDSA_P256_SHA256, 0x0000, keyId, h1);
        Bytes hashTbs1 = sha256(tbs1);
        BnPtr r1 = makeBn();
        BnPtr s1 = makeBn();
        ecdsaSignByHand(curve, d.get(), hashTbs1, k.get(), r1.get(), s1.get(), ctx.get());
        Bytes der1 = encodeEcdsaDer(r1.get(), s1.get());

        L3sgContainer c1{0x01, ALG_ECDSA_P256_SHA256, 0x0000, keyId, static_cast<uint16_t>(der1.size()), der1};
        writeFileBytes(s1Path, serializeL3sgContainer(c1), true);

        Bytes h2 = sha512StreamFile(m2Path, ok);
        Bytes tbs2 = buildL3sgTbs(0x01, ALG_ECDSA_P256_SHA256, 0x0000, keyId, h2);
        Bytes hashTbs2 = sha256(tbs2);
        BnPtr r2 = makeBn();
        BnPtr s2 = makeBn();
        ecdsaSignByHand(curve, d.get(), hashTbs2, k.get(), r2.get(), s2.get(), ctx.get());
        Bytes der2 = encodeEcdsaDer(r2.get(), s2.get());

        L3sgContainer c2{0x01, ALG_ECDSA_P256_SHA256, 0x0000, keyId, static_cast<uint16_t>(der2.size()), der2};
        writeFileBytes(s2Path, serializeL3sgContainer(c2), true);

        return RET_OK;
    }

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Unknown curve: " << curveName << endl;
        return RET_USAGE;
    }

    cout << "== Part 1: ECDSA " << curve.name << " ==" << endl;
    EvpPkeyPtr key(EVP_EC_gen(curve.name.c_str()));
    BnPtr d = makeBn();
    BIGNUM *rawD = d.get();
    EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_PRIV_KEY, &rawD);

    uint8_t pubBuf[133] = {0};
    size_t pubLen = 0;
    EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY, pubBuf, sizeof(pubBuf), &pubLen);
    EcAffinePoint Qpt = newAffinePoint();
    string err;
    decodeSec1Point(curve, Bytes(pubBuf, pubBuf + pubLen), Qpt, err, ctx.get());
    EcPointPtr Q(toOpenSslPoint(curve.grp.get(), Qpt, ctx.get()));

    string testMsg = "sample";
    Bytes h = sha256(Bytes(testMsg.begin(), testMsg.end()));
    BnPtr kTest = makeBn();
    BN_rand_range(kTest.get(), curve.n.get());
    BnPtr r = makeBn();
    BnPtr s = makeBn();
    ecdsaSignByHand(curve, d.get(), h, kTest.get(), r.get(), s.get(), ctx.get());

    if (!ecdsaVerifyByHand(curve, Q.get(), h, r.get(), s.get(), ctx.get())) {
        cout << "FAIL: verify by hand" << endl;
        return RET_CRYPTO;
    }

    cout << "== Part 2: deterministic nonce (RFC 6979, A.2.5) ==" << endl;
    BnPtr dRfc = makeBn();
    BIGNUM *rawDrfc = dRfc.get();
    BN_hex2bn(&rawDrfc, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

    BnPtr kExp = makeBn();
    BnPtr rExp = makeBn();
    BnPtr sExp = makeBn();
    BIGNUM *rkExp = kExp.get();
    BIGNUM *rrExp = rExp.get();
    BIGNUM *rsExp = sExp.get();
    BN_hex2bn(&rkExp, "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    BN_hex2bn(&rrExp, "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    BN_hex2bn(&rsExp, "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    BnPtr kRfc = rfc6979Nonce(curve, dRfc.get(), h);
    if (BN_cmp(kRfc.get(), kExp.get()) != 0) {
        cout << "FAIL: RFC 6979 k mismatch" << endl;
        return RET_CRYPTO;
    }

    BnPtr rRfc = makeBn();
    BnPtr sRfc = makeBn();
    ecdsaSignByHand(curve, dRfc.get(), h, kRfc.get(), rRfc.get(), sRfc.get(), ctx.get());
    if (BN_cmp(rRfc.get(), rExp.get()) != 0 || BN_cmp(sRfc.get(), sExp.get()) != 0) {
        cout << "FAIL: RFC 6979 (r, s) mismatch" << endl;
        return RET_CRYPTO;
    }

    char *kHex = BN_bn2hex(kRfc.get());
    char *rHex = BN_bn2hex(rRfc.get());
    char *sHex = BN_bn2hex(sRfc.get());

    string kStr(kHex), rStr(rHex), sStr(sHex);
    OPENSSL_free(kHex); OPENSSL_free(rHex); OPENSSL_free(sHex);

    cout << "All checks PASS, including RFC 6979:" << endl;
    cout << "k = " << kStr.substr(0, 8) << "..." << kStr.substr(kStr.size() - 6) << ", "
         << "r = " << rStr.substr(0, 8) << "..." << rStr.substr(rStr.size() - 6) << ", "
         << "s = " << sStr.substr(0, 8) << "..." << sStr.substr(sStr.size() - 6) << endl;

    return RET_OK;
}

int handleEcdsaRecover(int argc, char **argv) {
    string pubPath, m1Path, s1Path, m2Path, s2Path, outPrivPath;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--pub" || arg == "-pub") && i + 1 < argc) pubPath = argv[++i];
        else if ((arg == "--m1" || arg == "-m1") && i + 1 < argc) m1Path = argv[++i];
        else if ((arg == "--s1" || arg == "-s1") && i + 1 < argc) s1Path = argv[++i];
        else if ((arg == "--m2" || arg == "-m2") && i + 1 < argc) m2Path = argv[++i];
        else if ((arg == "--s2" || arg == "-s2") && i + 1 < argc) s2Path = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outPrivPath = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (pubPath.empty() || m1Path.empty() || s1Path.empty() ||
        m2Path.empty() || s2Path.empty() || outPrivPath.empty()) {
        cerr << "Usage: lab03 ecdsa-recover --pub <key> -m1 <f1> -s1 <s1> -m2 <f2> -s2 <s2> -out <priv> [--force]" << endl;
        return RET_USAGE;
    }

    if (!force && fileExists(outPrivPath)) {
        cerr << "Output file exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    EvpPkeyPtr pubKey;
    string err;
    if (!loadStrictKey(pubPath, false, pubKey, err)) {
        cerr << "Failed to load public key: " << err << endl;
        return RET_DATA;
    }

    Bytes s1Bytes, s2Bytes;
    if (!readFileBytes(s1Path, s1Bytes) || !readFileBytes(s2Path, s2Bytes)) {
        cerr << "Failed to read signature files" << endl;
        return RET_IO;
    }

    L3sgContainer c1, c2;
    if (!parseL3sgContainer(s1Bytes, c1, err) || !parseL3sgContainer(s2Bytes, c2, err)) {
        cerr << "Failed to parse signature container: " << err << endl;
        return RET_DATA;
    }

    BnPtr r1 = makeBn();
    BnPtr s1 = makeBn();
    BnPtr r2 = makeBn();
    BnPtr s2 = makeBn();
    if (!decodeEcdsaDer(c1.signature, r1.get(), s1.get()) ||
        !decodeEcdsaDer(c2.signature, r2.get(), s2.get())) {
        cerr << "Failed to decode DER signatures" << endl;
        return RET_DATA;
    }

    if (BN_cmp(r1.get(), r2.get()) != 0) {
        cout << "Reports that the nonces differ; no key written" << endl;
        return RET_CRYPTO;
    }

    string curveName = (c1.alg == ALG_ECDSA_P384_SHA384) ? "P-384" :
                       ((c1.alg == ALG_ECDSA_SECP256K1_SHA256) ? "secp256k1" : "P-256");

    BnCtxPtr ctx = makeBnCtx();
    EcCurve curve;
    if (!loadNamedCurve(curveName, curve, ctx.get())) {
        cerr << "Failed to load curve" << endl;
        return RET_INTERNAL;
    }

    bool ok = false;
    Bytes h1 = sha512StreamFile(m1Path, ok);
    Bytes h2 = sha512StreamFile(m2Path, ok);

    Bytes tbs1 = buildL3sgTbs(c1.version, c1.alg, c1.reserved, c1.keyId, h1);
    Bytes tbs2 = buildL3sgTbs(c2.version, c2.alg, c2.reserved, c2.keyId, h2);

    Bytes hash1 = (c1.alg == ALG_ECDSA_P384_SHA384) ? sha512(tbs1) : sha256(tbs1);
    Bytes hash2 = (c2.alg == ALG_ECDSA_P384_SHA384) ? sha512(tbs2) : sha256(tbs2);

    BnPtr e1 = ecdsaBits2Int(curve, hash1);
    BnPtr e2 = ecdsaBits2Int(curve, hash2);

    BnPtr num = makeBn();
    BnPtr den = makeBn();
    BnPtr kRec = makeBn();
    BnPtr dRec = makeBn();
    BnPtr t = makeBn();

    BN_mod_sub(num.get(), e1.get(), e2.get(), curve.n.get(), ctx.get());
    BN_mod_sub(den.get(), s1.get(), s2.get(), curve.n.get(), ctx.get());
    BN_mod_inverse(den.get(), den.get(), curve.n.get(), ctx.get());
    BN_mod_mul(kRec.get(), num.get(), den.get(), curve.n.get(), ctx.get());

    BN_mod_mul(t.get(), s1.get(), kRec.get(), curve.n.get(), ctx.get());
    BN_mod_sub(t.get(), t.get(), e1.get(), curve.n.get(), ctx.get());
    BN_mod_inverse(den.get(), r1.get(), curve.n.get(), ctx.get());
    BN_mod_mul(dRec.get(), t.get(), den.get(), curve.n.get(), ctx.get());

    uint8_t pubBuf[133] = {0};
    size_t pubLen = 0;
    EVP_PKEY_get_octet_string_param(pubKey.get(), OSSL_PKEY_PARAM_PUB_KEY, pubBuf, sizeof(pubBuf), &pubLen);
    EcPointPtr Qpub(EC_POINT_new(curve.grp.get()));
    EC_POINT_oct2point(curve.grp.get(), Qpub.get(), pubBuf, pubLen, ctx.get());

    EcPointPtr Qrec(EC_POINT_new(curve.grp.get()));
    EC_POINT_mul(curve.grp.get(), Qrec.get(), dRec.get(), nullptr, nullptr, ctx.get());

    bool matched = (EC_POINT_cmp(curve.grp.get(), Qrec.get(), Qpub.get(), ctx.get()) == 0);
    if (!matched) {
        BN_mod_add(den.get(), s1.get(), s2.get(), curve.n.get(), ctx.get());
        BN_mod_inverse(den.get(), den.get(), curve.n.get(), ctx.get());
        BN_mod_mul(kRec.get(), num.get(), den.get(), curve.n.get(), ctx.get());

        BN_mod_mul(t.get(), s1.get(), kRec.get(), curve.n.get(), ctx.get());
        BN_mod_sub(t.get(), t.get(), e1.get(), curve.n.get(), ctx.get());
        BN_mod_inverse(den.get(), r1.get(), curve.n.get(), ctx.get());
        BN_mod_mul(dRec.get(), t.get(), den.get(), curve.n.get(), ctx.get());

        EC_POINT_mul(curve.grp.get(), Qrec.get(), dRec.get(), nullptr, nullptr, ctx.get());
        matched = (EC_POINT_cmp(curve.grp.get(), Qrec.get(), Qpub.get(), ctx.get()) == 0);
    }

    if (!matched) {
        cerr << "Failed to verify recovered private key" << endl;
        return RET_CRYPTO;
    }

    ParamBldPtr bld(OSSL_PARAM_BLD_new());
    OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve.name.c_str(), 0);
    OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, dRec.get());
    OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pubBuf, pubLen);
    ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));

    EvpPkeyCtxPtr fctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY_fromdata_init(fctx.get());
    EVP_PKEY *rawPriv = nullptr;
    EVP_PKEY_fromdata(fctx.get(), &rawPriv, EVP_PKEY_KEYPAIR, params.get());
    EvpPkeyPtr recKey(rawPriv);

    if (!recKey) {
        cerr << "Failed to construct recovered EVP_PKEY" << endl;
        return RET_INTERNAL;
    }

    BioPtr bio(BIO_new_file(outPrivPath.c_str(), "wb"));
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), recKey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        cerr << "Failed to write recovered private key" << endl;
        return RET_IO;
    }

    cout << "Equal r reported; MATCH; key-check of the recovered key with the public key gives MATCH" << endl;
    return RET_OK;
}
