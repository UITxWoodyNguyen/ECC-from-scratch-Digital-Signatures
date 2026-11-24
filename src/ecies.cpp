#include "ecies.h"
#include "ec_keys.h"
#include "ec_math.h"

static Bytes deriveHkdfSha256(const Bytes &ikm, const Bytes &info, size_t outLen) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return {};

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return {};

    char digestName[] = "SHA256";
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digestName, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm.data()), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t *>(info.data()), info.size());
    params[3] = OSSL_PARAM_construct_end();

    Bytes out(outLen);
    if (EVP_KDF_derive(kctx, out.data(), outLen, params) <= 0) {
        out.clear();
    }
    EVP_KDF_CTX_free(kctx);
    return out;
}

static Bytes buildEciesInfo(const Bytes &ephPub, const Bytes &recipPub) {
    static const char label[] = "LAB03-ECIES-HKDF-SHA256-AES256GCM-v1";
    Bytes info(label, label + sizeof(label) - 1);
    info.pb(0x00);
    info.insert(info.end(), all(ephPub));
    info.insert(info.end(), all(recipPub));
    return info;
}

static Bytes getEciesEncodedPub(EVP_PKEY *key) {
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_EC) {
        uint8_t pubBuf[133] = {0};
        size_t pubLen = 0;
        if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pubBuf, sizeof(pubBuf), &pubLen) == 1) {
            char curveName[64] = {0};
            EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), nullptr);
            BnCtxPtr ctx = makeBnCtx();
            EcCurve curve;
            if (loadNamedCurve(curveName, curve, ctx.get())) {
                EcAffinePoint pt = newAffinePoint();
                string err;
                Bytes rawPub(pubBuf, pubBuf + pubLen);
                if (decodeSec1Point(curve, rawPub, pt, err, ctx.get())) {
                    return encodeSec1Point(curve, pt, false, ctx.get());
                }
            }
            return Bytes(pubBuf, pubBuf + pubLen);
        }
    } else if (type == EVP_PKEY_X25519) {
        size_t len = 0;
        EVP_PKEY_get_raw_public_key(key, nullptr, &len);
        if (len == 32) {
            Bytes out(32);
            EVP_PKEY_get_raw_public_key(key, out.data(), &len);
            return out;
        }
    }
    return {};
}

static EvpPkeyPtr createPublicKeyFromEncoded(uint8_t mode, const Bytes &encPub) {
    if (mode == 0x03) {
        if (encPub.size() != 65 || encPub[0] != 0x04) return nullptr;
        BnCtxPtr ctx = makeBnCtx();
        EcCurve curve;
        if (!loadNamedCurve("P-256", curve, ctx.get())) return nullptr;
        EcAffinePoint pt = newAffinePoint();
        string err;
        if (!decodeSec1Point(curve, encPub, pt, err, ctx.get())) return nullptr;

        ParamBldPtr bld(OSSL_PARAM_BLD_new());
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, const_cast<uint8_t *>(encPub.data()), encPub.size());
        ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));

        EvpPkeyCtxPtr fctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!fctx || EVP_PKEY_fromdata_init(fctx.get()) <= 0) return nullptr;

        EVP_PKEY *raw = nullptr;
        if (EVP_PKEY_fromdata(fctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0 || !raw) return nullptr;

        EvpPkeyPtr pkey(raw);
        EvpPkeyCtxPtr vctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
        if (!vctx || EVP_PKEY_public_check(vctx.get()) <= 0) return nullptr;
        return pkey;
    } else if (mode == 0x04) {
        if (encPub.size() != 32) return nullptr;
        bool allZero = true;
        for (uint8_t b : encPub) {
            if (b != 0) { allZero = false; break; }
        }
        if (allZero) return nullptr;

        EVP_PKEY *raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, encPub.data(), 32);
        if (!raw) return nullptr;
        return EvpPkeyPtr(raw);
    }
    return nullptr;
}

int handleEciesEncrypt(int argc, char **argv) {
    string pubKeyPath, inFilePath, outPkgPath;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--pub" || arg == "-pub") && i + 1 < argc) pubKeyPath = argv[++i];
        else if ((arg == "--in" || arg == "-in") && i + 1 < argc) inFilePath = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outPkgPath = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (pubKeyPath.empty() || inFilePath.empty() || outPkgPath.empty()) {
        cerr << "Usage: lab03 ecies-encrypt --pub <key> -in <file> -out <package> [--force]" << endl;
        return RET_USAGE;
    }

    if (!fileExists(inFilePath)) {
        cerr << "Input file not found: " << inFilePath << endl;
        return RET_IO;
    }

    if (!force && fileExists(outPkgPath)) {
        cerr << "Output package already exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    EvpPkeyPtr recipKey;
    string err;
    if (!loadStrictKey(pubKeyPath, false, recipKey, err)) {
        cerr << "Failed to load recipient public key: " << err << endl;
        return RET_DATA;
    }

    int recipType = EVP_PKEY_base_id(recipKey.get());
    uint8_t mode = 0;
    uint16_t elen = 0;
    if (recipType == EVP_PKEY_EC) {
        char curveName[64] = {0};
        EVP_PKEY_get_utf8_string_param(recipKey.get(), OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), nullptr);
        string c(curveName);
        if (c != "P-256" && c != "prime256v1" && c != "secp256r1") {
            cerr << "ECIES only supports P-256 and X25519" << endl;
            return RET_DATA;
        }
        mode = 0x03;
        elen = 65;
    } else if (recipType == EVP_PKEY_X25519) {
        mode = 0x04;
        elen = 32;
    } else {
        cerr << "Unsupported key type for ECIES" << endl;
        return RET_DATA;
    }

    EvpPkeyPtr ephKey;
    if (mode == 0x03) {
        ephKey.reset(EVP_EC_gen("P-256"));
    } else {
        ephKey.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519"));
    }
    if (!ephKey) {
        cerr << "Failed to generate ephemeral key" << endl;
        return RET_INTERNAL;
    }

    Bytes ephPub = getEciesEncodedPub(ephKey.get());
    Bytes recipPub = getEciesEncodedPub(recipKey.get());
    if (ephPub.size() != elen || recipPub.size() != elen) {
        cerr << "Encoded public key length mismatch" << endl;
        return RET_INTERNAL;
    }

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new_from_pkey(nullptr, ephKey.get(), nullptr));
    if (!dctx || EVP_PKEY_derive_init(dctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer_ex(dctx.get(), recipKey.get(), 1) <= 0) {
        cerr << "Key agreement setup failed" << endl;
        return RET_CRYPTO;
    }

    size_t zLen = 0;
    EVP_PKEY_derive(dctx.get(), nullptr, &zLen);
    Bytes Z(zLen);
    if (EVP_PKEY_derive(dctx.get(), Z.data(), &zLen) <= 0) {
        cerr << "Key derivation failed" << endl;
        return RET_CRYPTO;
    }
    ephKey.reset();

    Bytes info = buildEciesInfo(ephPub, recipPub);
    Bytes K = deriveHkdfSha256(Z, info, 32);
    secureCleanse(Z);

    if (K.size() != 32) {
        cerr << "HKDF derivation failed" << endl;
        return RET_CRYPTO;
    }

    Bytes nonce(12);
    if (RAND_bytes(nonce.data(), 12) != 1) {
        secureCleanse(K);
        cerr << "Random generation failed" << endl;
        return RET_INTERNAL;
    }

    ifstream inFile(inFilePath, ios::binary | ios::ate);
    if (!inFile.is_open()) {
        secureCleanse(K);
        cerr << "Failed to open input file" << endl;
        return RET_IO;
    }
    uint64_t fileSize = static_cast<uint64_t>(inFile.tellg());
    inFile.seekg(0, ios::beg);

    Bytes header;
    header.reserve(30 + elen);
    header.pb('L'); header.pb('3'); header.pb('P'); header.pb('K');
    header.pb(0x01);
    header.pb(mode);
    header.pb(0x00); header.pb(0x00);
    header.pb(static_cast<uint8_t>(elen >> 8));
    header.pb(static_cast<uint8_t>(elen & 0xFF));
    header.insert(header.end(), all(ephPub));
    header.insert(header.end(), all(nonce));
    FORD(s, 56, 0) {
        header.pb(static_cast<uint8_t>((fileSize >> s) & 0xFF));
        s -= 7;
    }

    ofstream outFile(outPkgPath, ios::binary | ios::trunc);
    if (!outFile.is_open()) {
        secureCleanse(K);
        cerr << "Failed to open output package: " << outPkgPath << endl;
        return RET_IO;
    }

    outFile.write(reinterpret_cast<const char *>(header.data()), header.size());

    EvpCipherCtxPtr cctx(EVP_CIPHER_CTX_new());
    if (!cctx || EVP_CipherInit_ex2(cctx.get(), EVP_aes_256_gcm(), K.data(), nonce.data(), 1, nullptr) != 1) {
        secureCleanse(K);
        cerr << "AES-GCM init failed" << endl;
        return RET_INTERNAL;
    }

    int len = 0;
    if (EVP_CipherUpdate(cctx.get(), nullptr, &len, header.data(), static_cast<int>(header.size())) != 1) {
        secureCleanse(K);
        cerr << "AES-GCM AAD failed" << endl;
        return RET_INTERNAL;
    }

    constexpr size_t CHUNK_SIZE = 64 * 1024;
    vector<char> inBuf(CHUNK_SIZE);
    vector<uint8_t> outBuf(CHUNK_SIZE + 16);

    while (inFile.read(inBuf.data(), CHUNK_SIZE) || inFile.gcount() > 0) {
        streamsize readBytes = inFile.gcount();
        if (EVP_CipherUpdate(cctx.get(), outBuf.data(), &len, reinterpret_cast<const uint8_t *>(inBuf.data()), static_cast<int>(readBytes)) != 1) {
            secureCleanse(K);
            cerr << "AES-GCM update failed" << endl;
            return RET_INTERNAL;
        }
        if (len > 0) {
            outFile.write(reinterpret_cast<const char *>(outBuf.data()), len);
        }
    }

    if (EVP_CipherFinal_ex(cctx.get(), outBuf.data(), &len) != 1) {
        secureCleanse(K);
        cerr << "AES-GCM final failed" << endl;
        return RET_INTERNAL;
    }
    if (len > 0) {
        outFile.write(reinterpret_cast<const char *>(outBuf.data()), len);
    }

    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(cctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) != 1) {
        secureCleanse(K);
        cerr << "AES-GCM tag generation failed" << endl;
        return RET_INTERNAL;
    }
    outFile.write(reinterpret_cast<const char *>(tag.data()), 16);

    secureCleanse(K);
    return RET_OK;
}

int handleEciesDecrypt(int argc, char **argv) {
    string privKeyPath, inPkgPath, outFilePath;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--priv" || arg == "-priv") && i + 1 < argc) privKeyPath = argv[++i];
        else if ((arg == "--in" || arg == "-in") && i + 1 < argc) inPkgPath = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outFilePath = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (privKeyPath.empty() || inPkgPath.empty() || outFilePath.empty()) {
        cerr << "Usage: lab03 ecies-decrypt --priv <key> -in <package> -out <file> [--force]" << endl;
        return RET_USAGE;
    }

    if (!fileExists(inPkgPath)) {
        cerr << "Package file not found: " << inPkgPath << endl;
        return RET_IO;
    }

    if (!force && fileExists(outFilePath)) {
        cerr << "Output file already exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    ifstream pkgFile(inPkgPath, ios::binary | ios::ate);
    if (!pkgFile.is_open()) {
        cerr << "Failed to open package: " << inPkgPath << endl;
        return RET_IO;
    }
    uint64_t totalPkgSize = static_cast<uint64_t>(pkgFile.tellg());
    pkgFile.seekg(0, ios::beg);

    if (totalPkgSize < 10) {
        cout << "Rejected: truncated package header" << endl;
        return RET_DATA;
    }

    uint8_t minHdr[10];
    pkgFile.read(reinterpret_cast<char *>(minHdr), 10);
    if (memcmp(minHdr, "L3PK\x01", 5) != 0) {
        cout << "Rejected: invalid magic or version" << endl;
        return RET_DATA;
    }

    uint8_t mode = minHdr[5];
    if (mode != 0x03 && mode != 0x04) {
        cout << "Rejected: unsupported mode" << endl;
        return RET_DATA;
    }
    if (minHdr[6] != 0x00 || minHdr[7] != 0x00) {
        cout << "Rejected: nonzero reserved field" << endl;
        return RET_DATA;
    }

    uint16_t elen = static_cast<uint16_t>((minHdr[8] << 8) | minHdr[9]);
    if ((mode == 0x03 && elen != 65) || (mode == 0x04 && elen != 32)) {
        cout << "Rejected: invalid ephemeral public key length for mode" << endl;
        return RET_DATA;
    }

    size_t headerLen = 30 + elen;
    if (totalPkgSize < headerLen + 16) {
        cout << "Rejected: package truncated" << endl;
        return RET_DATA;
    }

    pkgFile.seekg(0, ios::beg);
    Bytes header(headerLen);
    pkgFile.read(reinterpret_cast<char *>(header.data()), headerLen);

    Bytes ephPub(header.begin() + 10, header.begin() + 10 + elen);
    Bytes nonce(header.begin() + 10 + elen, header.begin() + 22 + elen);

    uint64_t ctLen = 0;
    REP(i, 0, 8) {
        ctLen = (ctLen << 8) | header[22 + elen + i];
    }

    if (totalPkgSize != headerLen + ctLen + 16) {
        cout << "Rejected: file size mismatch" << endl;
        return RET_DATA;
    }

    EvpPkeyPtr privKey;
    string err;
    if (!loadStrictKey(privKeyPath, true, privKey, err)) {
        cerr << "Failed to load private key: " << err << endl;
        return RET_DATA;
    }

    int privType = EVP_PKEY_base_id(privKey.get());
    if ((mode == 0x03 && privType != EVP_PKEY_EC) ||
        (mode == 0x04 && privType != EVP_PKEY_X25519)) {
        cout << "Rejected: key type mismatch with package mode" << endl;
        return RET_DATA;
    }

    EvpPkeyPtr ephKey = createPublicKeyFromEncoded(mode, ephPub);
    if (!ephKey) {
        if (mode == 0x03) {
            cout << "Rejected: invalid point" << endl;
            return RET_DATA;
        } else {
            cout << "Rejected (low-order point)" << endl;
            return RET_DATA;
        }
    }

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new_from_pkey(nullptr, privKey.get(), nullptr));
    if (!dctx || EVP_PKEY_derive_init(dctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer_ex(dctx.get(), ephKey.get(), 1) <= 0) {
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    size_t zLen = 0;
    if (EVP_PKEY_derive(dctx.get(), nullptr, &zLen) <= 0 || zLen == 0) {
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    Bytes Z(zLen);
    if (EVP_PKEY_derive(dctx.get(), Z.data(), &zLen) <= 0) {
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    bool allZeroZ = true;
    for (uint8_t b : Z) {
        if (b != 0) { allZeroZ = false; break; }
    }
    if (allZeroZ) {
        secureCleanse(Z);
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    Bytes recipPub = getEciesEncodedPub(privKey.get());
    Bytes info = buildEciesInfo(ephPub, recipPub);
    Bytes K = deriveHkdfSha256(Z, info, 32);
    secureCleanse(Z);

    Bytes tag(16);
    pkgFile.seekg(-16, ios::end);
    pkgFile.read(reinterpret_cast<char *>(tag.data()), 16);

    string partPath = outFilePath + ".part";
    ofstream partFile(partPath, ios::binary | ios::trunc);
    if (!partFile.is_open()) {
        secureCleanse(K);
        cerr << "Failed to create part file" << endl;
        return RET_IO;
    }

    EvpCipherCtxPtr cctx(EVP_CIPHER_CTX_new());
    if (!cctx || EVP_CipherInit_ex2(cctx.get(), EVP_aes_256_gcm(), K.data(), nonce.data(), 0, nullptr) != 1) {
        secureCleanse(K);
        partFile.close();
        removeFile(partPath);
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    int len = 0;
    if (EVP_CipherUpdate(cctx.get(), nullptr, &len, header.data(), static_cast<int>(header.size())) != 1) {
        secureCleanse(K);
        partFile.close();
        removeFile(partPath);
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    pkgFile.seekg(headerLen, ios::beg);
    uint64_t remainingCt = ctLen;
    constexpr size_t CHUNK_SIZE = 64 * 1024;
    vector<char> inBuf(CHUNK_SIZE);
    vector<uint8_t> outBuf(CHUNK_SIZE + 16);

    while (remainingCt > 0) {
        size_t toRead = static_cast<size_t>(min<uint64_t>(remainingCt, CHUNK_SIZE));
        pkgFile.read(inBuf.data(), toRead);
        streamsize got = pkgFile.gcount();
        if (got <= 0) break;
        if (EVP_CipherUpdate(cctx.get(), outBuf.data(), &len, reinterpret_cast<const uint8_t *>(inBuf.data()), static_cast<int>(got)) != 1) {
            break;
        }
        if (len > 0) {
            partFile.write(reinterpret_cast<const char *>(outBuf.data()), len);
        }
        remainingCt -= got;
    }

    if (EVP_CIPHER_CTX_ctrl(cctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) != 1) {
        secureCleanse(K);
        partFile.close();
        removeFile(partPath);
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    bool authOk = (EVP_CipherFinal_ex(cctx.get(), outBuf.data(), &len) == 1);
    if (authOk && len > 0) {
        partFile.write(reinterpret_cast<const char *>(outBuf.data()), len);
    }
    partFile.close();
    secureCleanse(K);

    if (!authOk) {
        ERR_clear_error();
        removeFile(partPath);
        cout << "decryption failed" << endl;
        return RET_CRYPTO;
    }

    if (!force && fileExists(outFilePath)) {
        removeFile(partPath);
        cerr << "Output file exists (use --force to overwrite)" << endl;
        return RET_IO;
    }
    removeFile(outFilePath);
    if (!renameFile(partPath, outFilePath)) {
        cerr << "Failed to rename part file to output file" << endl;
        return RET_IO;
    }

    return RET_OK;
}
