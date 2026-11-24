#include "eddsa.h"
#include "sigfile.h"
#include "ec_keys.h"
#include "rsa_sig.h"
#include "ecdsa.h"

EdPoint newEdPoint() {
    EdPoint p;
    p.x = makeBn();
    p.y = makeBn();
    BN_zero(p.x.get());
    BN_one(p.y.get());
    return p;
}

EdPoint copyEdPoint(const EdPoint &pt) {
    EdPoint copy;
    copy.x = makeBn();
    copy.y = makeBn();
    if (pt.x) BN_copy(copy.x.get(), pt.x.get());
    if (pt.y) BN_copy(copy.y.get(), pt.y.get());
    return copy;
}

void edPointAdd(const EdCurveContext &E, EdPoint &R, const EdPoint &P, const EdPoint &Q) {
    BnPtr a = makeBn();
    BnPtr b = makeBn();
    BnPtr c = makeBn();
    BnPtr t = makeBn();
    BnPtr x3 = makeBn();
    BnPtr y3 = makeBn();

    BN_mod_mul(a.get(), P.x.get(), Q.y.get(), E.p.get(), E.ctx.get());
    BN_mod_mul(b.get(), Q.x.get(), P.y.get(), E.p.get(), E.ctx.get());
    BN_mod_add(x3.get(), a.get(), b.get(), E.p.get(), E.ctx.get());

    BN_mod_mul(a.get(), P.y.get(), Q.y.get(), E.p.get(), E.ctx.get());
    BN_mod_mul(b.get(), P.x.get(), Q.x.get(), E.p.get(), E.ctx.get());
    BN_mod_add(y3.get(), a.get(), b.get(), E.p.get(), E.ctx.get());

    BN_mod_mul(c.get(), b.get(), a.get(), E.p.get(), E.ctx.get());
    BN_mod_mul(c.get(), c.get(), E.d.get(), E.p.get(), E.ctx.get());

    BN_one(t.get());
    BN_mod_add(t.get(), t.get(), c.get(), E.p.get(), E.ctx.get());
    BN_mod_inverse(t.get(), t.get(), E.p.get(), E.ctx.get());
    BN_mod_mul(x3.get(), x3.get(), t.get(), E.p.get(), E.ctx.get());

    BN_one(t.get());
    BN_mod_sub(t.get(), t.get(), c.get(), E.p.get(), E.ctx.get());
    BN_mod_inverse(t.get(), t.get(), E.p.get(), E.ctx.get());
    BN_mod_mul(y3.get(), y3.get(), t.get(), E.p.get(), E.ctx.get());

    BN_copy(R.x.get(), x3.get());
    BN_copy(R.y.get(), y3.get());
}

void edPointMul(const EdCurveContext &E, EdPoint &R, const BIGNUM *k, const EdPoint &P) {
    EdPoint acc = newEdPoint();
    int totalBits = BN_num_bits(k);
    for (int i = totalBits - 1; i >= 0; --i) {
        edPointAdd(E, acc, acc, acc);
        if (BN_is_bit_set(k, i)) {
            edPointAdd(E, acc, acc, P);
        }
    }
    R = copyEdPoint(acc);
}

Bytes edEncodePoint(const EdPoint &P) {
    Bytes out(32, 0);
    BN_bn2lebinpad(P.y.get(), out.data(), 32);
    if (BN_is_odd(P.x.get())) {
        out[31] |= 0x80;
    }
    return out;
}

bool edDecodePoint(const EdCurveContext &E, const Bytes &in, EdPoint &P) {
    if (in.size() != 32) return false;
    Bytes b = in;
    int sign = (b[31] >> 7) & 1;
    b[31] &= 0x7F;

    BnPtr y = makeBn();
    BN_lebin2bn(b.data(), 32, y.get());
    if (BN_cmp(y.get(), E.p.get()) >= 0) return false;

    BnPtr u = makeBn();
    BnPtr v = makeBn();
    BnPtr x = makeBn();

    BN_mod_sqr(u.get(), y.get(), E.p.get(), E.ctx.get());
    BN_mod_mul(v.get(), u.get(), E.d.get(), E.p.get(), E.ctx.get());
    BN_add_word(v.get(), 1);
    BN_sub_word(u.get(), 1);
    BN_nnmod(u.get(), u.get(), E.p.get(), E.ctx.get());

    if (!BN_mod_inverse(v.get(), v.get(), E.p.get(), E.ctx.get())) return false;
    BN_mod_mul(u.get(), u.get(), v.get(), E.p.get(), E.ctx.get());

    if (!BN_mod_sqrt(x.get(), u.get(), E.p.get(), E.ctx.get())) {
        ERR_clear_error();
        return false;
    }

    BnPtr checkSqr = makeBn();
    BN_mod_sqr(checkSqr.get(), x.get(), E.p.get(), E.ctx.get());
    if (BN_cmp(checkSqr.get(), u.get()) != 0) return false;

    if (BN_is_zero(x.get()) && sign == 1) return false;

    if (BN_is_odd(x.get()) != sign) {
        BN_sub(x.get(), E.p.get(), x.get());
    }

    BN_copy(P.x.get(), x.get());
    BN_copy(P.y.get(), y.get());
    return true;
}

static EdCurveContext initEd25519Context() {
    EdCurveContext E;
    E.ctx = makeBnCtx();
    E.p = makeBn();
    E.d = makeBn();
    E.L = makeBn();

    BN_set_word(E.p.get(), 1);
    BN_lshift(E.p.get(), E.p.get(), 255);
    BN_sub_word(E.p.get(), 19);

    BnPtr t = makeBn();
    BN_set_word(t.get(), 121666);
    BN_mod_inverse(t.get(), t.get(), E.p.get(), E.ctx.get());
    BN_set_word(E.d.get(), 121665);
    BN_mod_mul(E.d.get(), E.d.get(), t.get(), E.p.get(), E.ctx.get());
    BN_sub(E.d.get(), E.p.get(), E.d.get());

    BIGNUM *rawL = E.L.get();
    BN_dec2bn(&rawL, "7237005577332262213973186563042994240857116359379907606001950938285454250989");

    return E;
}

static EdPoint getEd25519BasePoint(const EdCurveContext &E) {
    Bytes Benc(32, 0x66);
    Benc[0] = 0x58;
    EdPoint B = newEdPoint();
    edDecodePoint(E, Benc, B);
    return B;
}

static BnPtr leModL(const EdCurveContext &E, const Bytes &h) {
    BnPtr r = makeBn();
    BN_lebin2bn(h.data(), static_cast<int>(h.size()), r.get());
    BN_nnmod(r.get(), r.get(), E.L.get(), E.ctx.get());
    return r;
}

bool eddsaEvpSign(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, Bytes &outSig) {
    (void)algId;
    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestSignInit(mctx.get(), nullptr, nullptr, nullptr, key) != 1) return false;

    size_t sigLen = 0;
    if (EVP_DigestSign(mctx.get(), nullptr, &sigLen, tbs.data(), tbs.size()) != 1) return false;
    outSig.resize(sigLen);
    if (EVP_DigestSign(mctx.get(), outSig.data(), &sigLen, tbs.data(), tbs.size()) != 1) return false;
    outSig.resize(sigLen);
    return true;
}

bool eddsaEvpVerify(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, const Bytes &sig) {
    (void)algId;
    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx || EVP_DigestVerifyInit(mctx.get(), nullptr, nullptr, nullptr, key) != 1) return false;

    int res = EVP_DigestVerify(mctx.get(), sig.data(), sig.size(), tbs.data(), tbs.size());
    if (res != 1) {
        ERR_clear_error();
        return false;
    }
    return true;
}

static Bytes ed25519SignByHand(const EdCurveContext &E, const EdPoint &B, const Bytes &seed, const Bytes &M) {
    Bytes h = sha512(seed);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    BnPtr s = makeBn();
    BN_lebin2bn(h.data(), 32, s.get());

    Bytes prefix(h.begin() + 32, h.end());

    EdPoint A = newEdPoint();
    edPointMul(E, A, s.get(), B);
    Bytes Aenc = edEncodePoint(A);

    Bytes rInput = prefix;
    rInput.insert(rInput.end(), all(M));
    BnPtr r = leModL(E, sha512(rInput));

    EdPoint R = newEdPoint();
    edPointMul(E, R, r.get(), B);
    Bytes Renc = edEncodePoint(R);

    Bytes kInput = Renc;
    kInput.insert(kInput.end(), all(Aenc));
    kInput.insert(kInput.end(), all(M));
    BnPtr k = leModL(E, sha512(kInput));

    BnPtr S = makeBn();
    BN_mod_mul(S.get(), k.get(), s.get(), E.L.get(), E.ctx.get());
    BN_mod_add(S.get(), S.get(), r.get(), E.L.get(), E.ctx.get());

    Bytes sig = Renc;
    Bytes sBytes(32, 0);
    BN_bn2lebinpad(S.get(), sBytes.data(), 32);
    sig.insert(sig.end(), all(sBytes));

    secureCleanse(h);
    return sig;
}

static bool ed25519VerifyByHand(const EdCurveContext &E, const EdPoint &B, const Bytes &Aenc, const Bytes &M, const Bytes &sig) {
    if (sig.size() != 64) return false;
    Bytes Renc(sig.begin(), sig.begin() + 32);
    Bytes sBytes(sig.begin() + 32, sig.end());

    EdPoint A = newEdPoint();
    EdPoint R = newEdPoint();
    if (!edDecodePoint(E, Aenc, A) || !edDecodePoint(E, Renc, R)) return false;

    BnPtr S = makeBn();
    BN_lebin2bn(sBytes.data(), 32, S.get());
    if (BN_cmp(S.get(), E.L.get()) >= 0) return false;

    Bytes kInput = Renc;
    kInput.insert(kInput.end(), all(Aenc));
    kInput.insert(kInput.end(), all(M));
    BnPtr k = leModL(E, sha512(kInput));

    EdPoint lhs = newEdPoint();
    edPointMul(E, lhs, S.get(), B);

    EdPoint rhs = newEdPoint();
    edPointMul(E, rhs, k.get(), A);
    edPointAdd(E, rhs, rhs, R);

    return (BN_cmp(lhs.x.get(), rhs.x.get()) == 0 && BN_cmp(lhs.y.get(), rhs.y.get()) == 0);
}

int handleEd25519Demo() {
    EdCurveContext E = initEd25519Context();
    EdPoint B = getEd25519BasePoint(E);

    // RFC 8032 Section 7.1 Test 1 (M empty)
    Bytes seed1 = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    Bytes expA1 = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    Bytes expSig1 = fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    Bytes sig1 = ed25519SignByHand(E, B, seed1, {});
    if (sig1 != expSig1) {
        cout << "FAIL: Test 1 signature mismatch" << endl;
        return RET_CRYPTO;
    }
    if (!ed25519VerifyByHand(E, B, expA1, {}, sig1)) {
        cout << "FAIL: Test 1 verification failed" << endl;
        return RET_CRYPTO;
    }

    // RFC 8032 Section 7.1 Test 2 (M = 72)
    Bytes seed2 = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    Bytes expA2 = fromHex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    Bytes m2 = fromHex("72");
    Bytes expSig2 = fromHex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    Bytes sig2 = ed25519SignByHand(E, B, seed2, m2);
    if (sig2 != expSig2) {
        cout << "FAIL: Test 2 signature mismatch" << endl;
        return RET_CRYPTO;
    }
    if (!ed25519VerifyByHand(E, B, expA2, m2, sig2)) {
        cout << "FAIL: Test 2 verification failed" << endl;
        return RET_CRYPTO;
    }

    // RFC 8032 Section 7.1 Test 3 (M = af82)
    Bytes seed3 = fromHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    Bytes expA3 = fromHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    Bytes m3 = fromHex("af82");
    Bytes expSig3 = fromHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

    Bytes sig3 = ed25519SignByHand(E, B, seed3, m3);
    if (sig3 != expSig3) {
        cout << "FAIL: Test 3 signature mismatch" << endl;
        return RET_CRYPTO;
    }
    if (!ed25519VerifyByHand(E, B, expA3, m3, sig3)) {
        cout << "FAIL: Test 3 verification failed" << endl;
        return RET_CRYPTO;
    }

    // Cross-verify with OpenSSL
    EvpPkeyPtr osslKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed1.data(), 32));
    string testText = "Transfer 100 EUR to Alice";
    Bytes testM(testText.begin(), testText.end());
    Bytes handSig = ed25519SignByHand(E, B, seed1, testM);
    Bytes osslSig;
    eddsaEvpSign(osslKey.get(), ALG_ED25519, testM, osslSig);

    if (handSig != osslSig) {
        cout << "FAIL: OpenSSL and Hand Ed25519 signature mismatch" << endl;
        return RET_CRYPTO;
    }
    if (!eddsaEvpVerify(osslKey.get(), ALG_ED25519, testM, handSig)) {
        cout << "FAIL: OpenSSL failed to verify Hand signature" << endl;
        return RET_CRYPTO;
    }

    // Malleability check: S replaced by S + L
    BnPtr S = makeBn();
    BN_lebin2bn(handSig.data() + 32, 32, S.get());
    BN_add(S.get(), S.get(), E.L.get());
    Bytes twinSig = handSig;
    BN_bn2lebinpad(S.get(), twinSig.data() + 32, 32);

    if (ed25519VerifyByHand(E, B, expA1, testM, twinSig)) {
        cout << "FAIL: Hand verifier accepted S + L" << endl;
        return RET_CRYPTO;
    }
    if (eddsaEvpVerify(osslKey.get(), ALG_ED25519, testM, twinSig)) {
        cout << "FAIL: OpenSSL accepted S + L" << endl;
        return RET_CRYPTO;
    }

    string s1Hex = toHex(sig1, false);
    string s2Hex = toHex(sig2, false);
    string s3Hex = toHex(sig3, false);
    string a1Hex = toHex(expA1, false);

    cout << "RFC 8032 test 1 (M empty): A = " << a1Hex.substr(0, 8) << "..." << a1Hex.substr(a1Hex.size() - 4)
         << ", signature " << s1Hex.substr(0, 8) << "..." << s1Hex.substr(s1Hex.size() - 6)
         << "; test 2 (M = 72): signature " << s2Hex.substr(0, 8) << "..." << s2Hex.substr(s2Hex.size() - 6)
         << "; test 3 (M = af82): signature " << s3Hex.substr(0, 8) << "..." << s3Hex.substr(s3Hex.size() - 6)
         << "; all PASS" << endl;

    return RET_OK;
}

int handleSigBench(int argc, char **argv) {
    double durationSec = 0.2;
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--seconds" || arg == "-seconds") && i + 1 < argc) {
            durationSec = stod(argv[++i]);
        }
    }

    struct BenchmarkAlg {
        const char *name;
        const char *type;
        const char *curve;
        size_t rsaBits;
        uint8_t algId;
    };

    const BenchmarkAlg algs[] = {
        {"RSA-2048 PKCS1 v1.5", "RSA", nullptr, 2048, ALG_RSA_PKCS1_SHA256},
        {"RSA-3072 PSS", "RSA", nullptr, 3072, ALG_RSA_PSS_SHA256},
        {"ECDSA P-256", "EC", "P-256", 0, ALG_ECDSA_P256_SHA256},
        {"ECDSA P-384", "EC", "P-384", 0, ALG_ECDSA_P384_SHA384},
        {"ECDSA secp256k1", "EC", "secp256k1", 0, ALG_ECDSA_SECP256K1_SHA256},
        {"Ed25519", "ED25519", nullptr, 0, ALG_ED25519},
        {"Ed448", "ED448", nullptr, 0, ALG_ED448}
    };

    cout << "algorithm                 SPKI (B)   sig (B)     sign/s   verify/s" << endl;

    string sample = "benchmark test message for digital signatures comparison";
    Bytes msg(sample.begin(), sample.end());

    for (const auto &item : algs) {
        EvpPkeyPtr key;
        if (string(item.type) == "RSA") {
            key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", item.rsaBits));
        } else if (string(item.type) == "EC") {
            key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", item.curve));
        } else {
            key.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, item.type));
        }

        if (!key) continue;

        int pubLen = i2d_PUBKEY(key.get(), nullptr);
        Bytes sig;

        if (item.algId == ALG_RSA_PKCS1_SHA256 || item.algId == ALG_RSA_PSS_SHA256) {
            rsaEvpSign(key.get(), item.algId, msg, sig);
        } else if (item.algId == ALG_ECDSA_P256_SHA256 || item.algId == ALG_ECDSA_P384_SHA384 || item.algId == ALG_ECDSA_SECP256K1_SHA256) {
            ecdsaEvpSign(key.get(), item.algId, msg, sig);
        } else {
            eddsaEvpSign(key.get(), item.algId, msg, sig);
        }

        using clock = chrono::high_resolution_clock;
        int signCount = 0;
        auto t0 = clock::now();
        while (chrono::duration<double>(clock::now() - t0).count() < durationSec) {
            Bytes tempSig;
            if (item.algId == ALG_RSA_PKCS1_SHA256 || item.algId == ALG_RSA_PSS_SHA256) {
                rsaEvpSign(key.get(), item.algId, msg, tempSig);
            } else if (item.algId == ALG_ECDSA_P256_SHA256 || item.algId == ALG_ECDSA_P384_SHA384 || item.algId == ALG_ECDSA_SECP256K1_SHA256) {
                ecdsaEvpSign(key.get(), item.algId, msg, tempSig);
            } else {
                eddsaEvpSign(key.get(), item.algId, msg, tempSig);
            }
            ++signCount;
        }
        double signDuration = chrono::duration<double>(clock::now() - t0).count();
        double signRate = signCount / signDuration;

        int verifyCount = 0;
        auto t1 = clock::now();
        while (chrono::duration<double>(clock::now() - t1).count() < durationSec) {
            string errStr;
            bool vOk = false;
            if (item.algId == ALG_RSA_PKCS1_SHA256 || item.algId == ALG_RSA_PSS_SHA256) {
                vOk = rsaEvpVerify(key.get(), item.algId, msg, sig);
            } else if (item.algId == ALG_ECDSA_P256_SHA256 || item.algId == ALG_ECDSA_P384_SHA384 || item.algId == ALG_ECDSA_SECP256K1_SHA256) {
                vOk = ecdsaEvpVerify(key.get(), item.algId, msg, sig, false, errStr);
            } else {
                vOk = eddsaEvpVerify(key.get(), item.algId, msg, sig);
            }
            if (!vOk) break;
            ++verifyCount;
        }
        double verifyDuration = chrono::duration<double>(clock::now() - t1).count();
        double verifyRate = verifyCount / verifyDuration;

        cout << left << setw(25) << item.name
             << right << setw(10) << pubLen
             << setw(10) << sig.size()
             << setw(11) << static_cast<long>(signRate)
             << setw(11) << static_cast<long>(verifyRate) << endl;
    }

    return RET_OK;
}
