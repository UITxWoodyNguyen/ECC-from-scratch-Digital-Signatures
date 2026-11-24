#include "rsa_sig.h"
#include "sigfile.h"

Bytes mgf1Sha256(const Bytes &seed, size_t maskLen) {
    Bytes t;
    t.reserve(maskLen + 32);
    for (uint32_t c = 0; t.size() < maskLen; ++c) {
        Bytes blk = seed;
        blk.pb(static_cast<uint8_t>((c >> 24) & 0xFF));
        blk.pb(static_cast<uint8_t>((c >> 16) & 0xFF));
        blk.pb(static_cast<uint8_t>((c >> 8) & 0xFF));
        blk.pb(static_cast<uint8_t>(c & 0xFF));
        Bytes h = sha256(blk);
        t.insert(t.end(), all(h));
    }
    t.resize(maskLen);
    return t;
}

Bytes rsaPrimitive(const Bytes &msgBytes, const BIGNUM *exp, const BIGNUM *n, BN_CTX *ctx) {
    BnPtr xi = makeBn();
    BnPtr yi = makeBn();
    BN_bin2bn(msgBytes.data(), static_cast<int>(msgBytes.size()), xi.get());
    if (BN_cmp(xi.get(), n) >= 0) return {};
    BN_mod_exp(yi.get(), xi.get(), exp, n, ctx);
    size_t k = static_cast<size_t>(BN_num_bytes(n));
    Bytes y(k, 0);
    BN_bn2binpad(yi.get(), y.data(), static_cast<int>(k));
    return y;
}

Bytes emsaPkcs1v15Encode(const Bytes &M, size_t k) {
    static const uint8_t kSha256Prefix[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    Bytes T(kSha256Prefix, kSha256Prefix + 19);
    Bytes h = sha256(M);
    T.insert(T.end(), all(h));

    if (k < T.size() + 11) return {};
    Bytes EM;
    EM.reserve(k);
    EM.pb(0x00);
    EM.pb(0x01);
    size_t psLen = k - T.size() - 3;
    EM.insert(EM.end(), psLen, 0xFF);
    EM.pb(0x00);
    EM.insert(EM.end(), all(T));
    return EM;
}

Bytes emsaPssEncode(const Bytes &M, size_t emBits, size_t sLen) {
    size_t emLen = (emBits + 7) / 8;
    constexpr size_t hLen = 32;
    if (emLen < hLen + sLen + 2) return {};

    Bytes mHash = sha256(M);
    Bytes salt(sLen);
    if (sLen > 0) {
        RAND_bytes(salt.data(), static_cast<int>(sLen));
    }

    Bytes Mp(8, 0x00);
    Mp.insert(Mp.end(), all(mHash));
    Mp.insert(Mp.end(), all(salt));
    Bytes H = sha256(Mp);

    size_t dbLen = emLen - hLen - 1;
    Bytes DB(dbLen - sLen - 1, 0x00);
    DB.pb(0x01);
    DB.insert(DB.end(), all(salt));

    Bytes mask = mgf1Sha256(H, dbLen);
    REP(i, 0, dbLen) {
        DB[i] ^= mask[i];
    }

    uint8_t topMask = static_cast<uint8_t>(0xFF >> (8 * emLen - emBits));
    DB[0] &= topMask;

    Bytes EM;
    EM.reserve(emLen);
    EM.insert(EM.end(), all(DB));
    EM.insert(EM.end(), all(H));
    EM.pb(0xBC);
    return EM;
}

bool emsaPssVerify(const Bytes &M, const Bytes &EMin, size_t emBits, size_t sLen) {
    size_t emLen = (emBits + 7) / 8;
    constexpr size_t hLen = 32;
    if (EMin.size() < emLen) return false;

    Bytes EM(EMin.end() - emLen, EMin.end());
    if (EM.back() != 0xBC) return false;

    size_t dbLen = emLen - hLen - 1;
    Bytes DB(EM.begin(), EM.begin() + dbLen);
    Bytes H(EM.begin() + dbLen, EM.end() - 1);

    uint8_t topMask = static_cast<uint8_t>(0xFF << (8 - (8 * emLen - emBits)));
    if (8 * emLen > emBits && (DB[0] & topMask) != 0) return false;

    Bytes mask = mgf1Sha256(H, dbLen);
    REP(i, 0, dbLen) {
        DB[i] ^= mask[i];
    }
    DB[0] &= static_cast<uint8_t>(0xFF >> (8 * emLen - emBits));

    size_t psLen = dbLen - sLen - 1;
    REP(i, 0, psLen) {
        if (DB[i] != 0x00) return false;
    }
    if (DB[psLen] != 0x01) return false;

    Bytes salt(DB.begin() + psLen + 1, DB.end());
    Bytes mHash = sha256(M);
    Bytes Mp(8, 0x00);
    Mp.insert(Mp.end(), all(mHash));
    Mp.insert(Mp.end(), all(salt));
    Bytes expH = sha256(Mp);

    return (H == expH);
}

bool rsaEvpSign(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, Bytes &outSig) {
    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx) return false;

    EVP_PKEY_CTX *pctx = nullptr;
    if (EVP_DigestSignInit(mctx.get(), &pctx, EVP_sha256(), nullptr, key) != 1) return false;

    if (algId == ALG_RSA_PKCS1_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) return false;
    } else if (algId == ALG_RSA_PSS_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) return false;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) <= 0) return false;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) return false;
    } else {
        return false;
    }

    size_t sigLen = 0;
    if (EVP_DigestSign(mctx.get(), nullptr, &sigLen, tbs.data(), tbs.size()) != 1) return false;
    outSig.resize(sigLen);
    if (EVP_DigestSign(mctx.get(), outSig.data(), &sigLen, tbs.data(), tbs.size()) != 1) {
        outSig.clear();
        return false;
    }
    outSig.resize(sigLen);
    return true;
}

bool rsaEvpVerify(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, const Bytes &sig) {
    EvpMdCtxPtr mctx(EVP_MD_CTX_new());
    if (!mctx) return false;

    EVP_PKEY_CTX *pctx = nullptr;
    if (EVP_DigestVerifyInit(mctx.get(), &pctx, EVP_sha256(), nullptr, key) != 1) return false;

    if (algId == ALG_RSA_PKCS1_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) return false;
    } else if (algId == ALG_RSA_PSS_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) return false;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) <= 0) return false;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) return false;
    } else {
        return false;
    }

    int res = EVP_DigestVerify(mctx.get(), sig.data(), sig.size(), tbs.data(), tbs.size());
    if (res != 1) {
        ERR_clear_error();
        return false;
    }
    return true;
}

int handleRsaSigDemo() {
    BnCtxPtr ctx = makeBnCtx();
    EvpPkeyPtr rsaKey(EVP_RSA_gen(2048));
    if (!rsaKey) {
        cerr << "Failed to generate RSA-2048" << endl;
        return RET_INTERNAL;
    }

    BnPtr n = makeBn();
    BnPtr e = makeBn();
    BnPtr d = makeBn();
    BIGNUM *rawN = n.get();
    BIGNUM *rawE = e.get();
    BIGNUM *rawD = d.get();
    EVP_PKEY_get_bn_param(rsaKey.get(), OSSL_PKEY_PARAM_RSA_N, &rawN);
    EVP_PKEY_get_bn_param(rsaKey.get(), OSSL_PKEY_PARAM_RSA_E, &rawE);
    EVP_PKEY_get_bn_param(rsaKey.get(), OSSL_PKEY_PARAM_RSA_D, &rawD);

    // Part 1: Textbook RSA
    cout << "== Part 1: textbook RSA signatures, RSA-2048 (INSECURE) ==" << endl;
    BnPtr s1 = makeBn();
    BnPtr m1 = makeBn();
    BN_rand_range(s1.get(), n.get());
    BN_mod_exp(m1.get(), s1.get(), e.get(), n.get(), ctx.get());

    BnPtr v1 = makeBn();
    BN_mod_exp(v1.get(), s1.get(), e.get(), n.get(), ctx.get());
    if (BN_cmp(v1.get(), m1.get()) != 0) {
        cout << "FAIL: Forgery 1" << endl;
        return RET_CRYPTO;
    }
    cout << "[PASS] forgery 1: (s^e mod n, s) verifies without d" << endl;

    string targetMsg = "I, Alice, owe Mallory 1000000 USD.";
    BnPtr mTarget = makeBn();
    BN_bin2bn(reinterpret_cast<const uint8_t *>(targetMsg.data()), static_cast<int>(targetMsg.size()), mTarget.get());

    BnPtr r = makeBn();
    BnPtr rinv = makeBn();
    do {
        BN_rand_range(r.get(), n.get());
    } while (!BN_mod_inverse(rinv.get(), r.get(), n.get(), ctx.get()));

    BnPtr rExp = makeBn();
    BN_mod_exp(rExp.get(), r.get(), e.get(), n.get(), ctx.get());
    BnPtr mBlind = makeBn();
    BN_mod_mul(mBlind.get(), mTarget.get(), rExp.get(), n.get(), ctx.get());

    BnPtr sBlind = makeBn();
    BN_mod_exp(sBlind.get(), mBlind.get(), d.get(), n.get(), ctx.get());

    BnPtr sUnblind = makeBn();
    BN_mod_mul(sUnblind.get(), sBlind.get(), rinv.get(), n.get(), ctx.get());

    BnPtr v2 = makeBn();
    BN_mod_exp(v2.get(), sUnblind.get(), e.get(), n.get(), ctx.get());
    if (BN_cmp(v2.get(), mTarget.get()) != 0) {
        cout << "FAIL: Forgery 2" << endl;
        return RET_CRYPTO;
    }
    cout << "[PASS] forgery 2: Alice never saw m*, yet (m*, s) verifies" << endl;

    // Part 2: EMSA-PKCS1-v1_5
    cout << "== Part 2: RSASSA-PKCS1-v1_5 (SHA-256) ==" << endl;
    string msgText = "Pay 100 USD to Alice";
    Bytes msgBytes(msgText.begin(), msgText.end());
    size_t kLen = static_cast<size_t>(BN_num_bytes(n.get()));
    Bytes em = emsaPkcs1v15Encode(msgBytes, kLen);

    Bytes sHand = rsaPrimitive(em, d.get(), n.get(), ctx.get());
    Bytes sEvp;
    rsaEvpSign(rsaKey.get(), ALG_RSA_PKCS1_SHA256, msgBytes, sEvp);

    if (sHand != sEvp) {
        cout << "FAIL: PKCS1 v1.5 byte-for-byte mismatch" << endl;
        return RET_CRYPTO;
    }
    cout << "[PASS] our signature == EVP_DigestSign (byte for byte)" << endl;

    if (!rsaEvpVerify(rsaKey.get(), ALG_RSA_PKCS1_SHA256, msgBytes, sHand)) {
        cout << "FAIL: OpenSSL failed to verify our signature" << endl;
        return RET_CRYPTO;
    }
    cout << "[PASS] OpenSSL verifies our signature" << endl;

    // Part 3: EMSA-PSS
    cout << "== Part 3: RSASSA-PSS (SHA-256, sLen = 32) ==" << endl;
    size_t emBits = static_cast<size_t>(BN_num_bits(n.get()) - 1);
    Bytes emPss = emsaPssEncode(msgBytes, emBits, 32);
    Bytes sPssHand = rsaPrimitive(emPss, d.get(), n.get(), ctx.get());

    if (!rsaEvpVerify(rsaKey.get(), ALG_RSA_PSS_SHA256, msgBytes, sPssHand)) {
        cout << "FAIL: OpenSSL failed to verify hand PSS signature" << endl;
        return RET_CRYPTO;
    }
    cout << "[PASS] OpenSSL verifies our PSS signature" << endl;

    Bytes sPssEvp;
    rsaEvpSign(rsaKey.get(), ALG_RSA_PSS_SHA256, msgBytes, sPssEvp);
    Bytes emRecovered = rsaPrimitive(sPssEvp, e.get(), n.get(), ctx.get());
    if (!emsaPssVerify(msgBytes, emRecovered, emBits, 32)) {
        cout << "FAIL: our emsaPssVerify failed on OpenSSL signature" << endl;
        return RET_CRYPTO;
    }
    cout << "[PASS] our EMSA-PSS-VERIFY accepts OpenSSL's signature" << endl;

    cout << "All checks PASS" << endl;
    return RET_OK;
}
