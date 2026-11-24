#include "ec_keys.h"
#include "ec_math.h"

bool isAllowedAlgorithm(const string &algName) {
    static const vector<string> allowed = {
        "rsa-2048", "rsa-3072", "rsa-4096",
        "P-256", "P-384", "secp256k1",
        "X25519", "Ed25519", "Ed448"
    };
    for (const string &s : allowed) {
        if (s == algName) return true;
    }
    return false;
}

string normalizeAlgName(const string &algName) {
    if (algName == "p-256" || algName == "P256" || algName == "prime256v1") return "P-256";
    if (algName == "p-384" || algName == "P384" || algName == "secp384r1") return "P-384";
    if (algName == "secp256k1") return "secp256k1";
    if (algName == "x25519" || algName == "X25519") return "X25519";
    if (algName == "ed25519" || algName == "Ed25519" || algName == "ED25519") return "Ed25519";
    if (algName == "ed448" || algName == "Ed448" || algName == "ED448") return "Ed448";
    if (algName == "rsa-2048") return "rsa-2048";
    if (algName == "rsa-3072") return "rsa-3072";
    if (algName == "rsa-4096") return "rsa-4096";
    return algName;
}

bool generateKeyPair(const string &algName, EvpPkeyPtr &outKey) {
    string norm = normalizeAlgName(algName);
    EVP_PKEY *raw = nullptr;
    if (norm == "rsa-2048") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", (size_t)2048);
    } else if (norm == "rsa-3072") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", (size_t)3072);
    } else if (norm == "rsa-4096") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", (size_t)4096);
    } else if (norm == "P-256") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    } else if (norm == "P-384") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384");
    } else if (norm == "secp256k1") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "secp256k1");
    } else if (norm == "X25519") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    } else if (norm == "Ed25519") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    } else if (norm == "Ed448") {
        raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
    }

    if (!raw) return false;
    outKey.reset(raw);
    return true;
}

bool loadStrictKey(const string &filePath, bool isPrivate, EvpPkeyPtr &outKey, string &errReason) {
    Bytes fileData;
    if (!readFileBytes(filePath, fileData) || fileData.empty()) {
        errReason = "could not read file";
        return false;
    }

    EVP_PKEY *raw = nullptr;
    BioPtr bio(BIO_new_mem_buf(fileData.data(), static_cast<int>(fileData.size())));
    if (!bio) {
        errReason = "memory allocation error";
        return false;
    }

    if (isPrivate) {
        raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        if (!raw) {
            ERR_clear_error();
            BIO_reset(bio.get());
            raw = d2i_PKCS8PrivateKey_bio(bio.get(), nullptr, nullptr, nullptr);
            if (!raw) {
                ERR_clear_error();
                BIO_reset(bio.get());
                raw = d2i_PrivateKey_bio(bio.get(), nullptr);
            }
        }
    } else {
        raw = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        if (!raw) {
            ERR_clear_error();
            BIO_reset(bio.get());
            raw = d2i_PUBKEY_bio(bio.get(), nullptr);
        }
    }

    if (!raw) {
        errReason = "failed to parse key (neither PEM nor DER format)";
        return false;
    }
    outKey.reset(raw);

    int keyType = EVP_PKEY_base_id(outKey.get());
    if (keyType == EVP_PKEY_EC) {
        int isExplicit = 0;
        if (EVP_PKEY_get_int_param(outKey.get(), OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, &isExplicit) == 1) {
            if (isExplicit == 1) {
                errReason = "explicit parameters";
                outKey.reset();
                return false;
            }
        }

        char curveName[64] = {0};
        if (EVP_PKEY_get_utf8_string_param(outKey.get(), OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), nullptr) != 1) {
            errReason = "missing curve name";
            outKey.reset();
            return false;
        }

        string cName(curveName);
        if (cName != "prime256v1" && cName != "P-256" && cName != "secp256r1" &&
            cName != "secp384r1" && cName != "P-384" &&
            cName != "secp256k1") {
            errReason = "unsupported EC curve: " + cName;
            outKey.reset();
            return false;
        }
    } else if (keyType == EVP_PKEY_RSA || keyType == EVP_PKEY_RSA_PSS) {
        int bits = EVP_PKEY_get_bits(outKey.get());
        if (bits < 2048) {
            errReason = "RSA modulus too short";
            outKey.reset();
            return false;
        }
    } else if (keyType == EVP_PKEY_X25519 || keyType == EVP_PKEY_ED25519 || keyType == EVP_PKEY_ED448) {
    } else {
        errReason = "unsupported algorithm type";
        outKey.reset();
        return false;
    }

    EvpPkeyCtxPtr vctx(EVP_PKEY_CTX_new_from_pkey(nullptr, outKey.get(), nullptr));
    if (!vctx || EVP_PKEY_public_check(vctx.get()) <= 0) {
        errReason = "EVP_PKEY_public_check failed";
        outKey.reset();
        return false;
    }

    return true;
}

string getKeyAlgorithmName(EVP_PKEY *key) {
    if (!key) return "unknown";
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_EC) {
        char curveName[64] = {0};
        if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), nullptr) == 1) {
            string c(curveName);
            if (c == "prime256v1" || c == "secp256r1") return "P-256";
            if (c == "secp384r1") return "P-384";
            return c;
        }
        return "EC";
    }
    if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
        int bits = EVP_PKEY_get_bits(key);
        return "RSA-" + to_string(bits);
    }
    if (type == EVP_PKEY_X25519) return "X25519";
    if (type == EVP_PKEY_ED25519) return "Ed25519";
    if (type == EVP_PKEY_ED448) return "Ed448";
    return "unknown";
}

string getKeyCurveName(EVP_PKEY *key) {
    if (!key) return "none";
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_EC) {
        char curveName[64] = {0};
        if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), nullptr) == 1) {
            return string(curveName);
        }
    }
    if (type == EVP_PKEY_X25519) return "Curve25519";
    if (type == EVP_PKEY_ED25519) return "edwards25519";
    if (type == EVP_PKEY_ED448) return "edwards448";
    return "none";
}

int getKeySecurityLevel(EVP_PKEY *key) {
    if (!key) return 0;
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_EC) {
        int bits = EVP_PKEY_get_bits(key);
        if (bits >= 384) return 192;
        return 128;
    }
    if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
        int bits = EVP_PKEY_get_bits(key);
        if (bits >= 4096) return 152;
        if (bits >= 3072) return 128;
        return 112;
    }
    if (type == EVP_PKEY_X25519 || type == EVP_PKEY_ED25519) return 128;
    if (type == EVP_PKEY_ED448) return 224;
    return 128;
}

Bytes getPublicKeyRepresentation(EVP_PKEY *key) {
    if (!key) return {};
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
                Bytes uncomp(pubBuf, pubBuf + pubLen);
                if (decodeSec1Point(curve, uncomp, pt, err, ctx.get())) {
                    return encodeSec1Point(curve, pt, true, ctx.get());
                }
            }
            return Bytes(pubBuf, pubBuf + pubLen);
        }
    } else if (type == EVP_PKEY_X25519 || type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) {
        size_t len = 0;
        EVP_PKEY_get_raw_public_key(key, nullptr, &len);
        if (len > 0) {
            Bytes out(len);
            EVP_PKEY_get_raw_public_key(key, out.data(), &len);
            return out;
        }
    } else if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
        BnPtr n = makeBn();
        BIGNUM *rawN = n.get();
        if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &rawN) == 1) {
            size_t nBytes = (size_t)BN_num_bytes(rawN);
            Bytes out(nBytes);
            BN_bn2binpad(rawN, out.data(), (int)nBytes);
            return out;
        }
    }
    return {};
}

int handleKeyGen(int argc, char **argv) {
    string alg;
    string outDir = ".";
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--alg" || arg == "-alg") && i + 1 < argc) alg = argv[++i];
        else if ((arg == "--out-dir" || arg == "-out-dir") && i + 1 < argc) outDir = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (alg.empty()) {
        cerr << "Usage: lab03 keygen --alg <name> --out-dir <dir> [--force]" << endl;
        return RET_USAGE;
    }

    string normAlg = normalizeAlgName(alg);
    if (!isAllowedAlgorithm(normAlg)) {
        cerr << "Unsupported algorithm: " << alg << endl;
        return RET_USAGE;
    }

    if (!createDirectories(outDir)) {
        cerr << "Could not create directory: " << outDir << endl;
        return RET_IO;
    }

    EvpPkeyPtr key;
    if (!generateKeyPair(normAlg, key)) {
        cerr << "Key generation failed for " << normAlg << endl;
        return RET_INTERNAL;
    }

    string prefix = outDir + "/" + normAlg;
    string privPemPath = prefix + "_private.pem";
    string privDerPath = prefix + "_private.der";
    string pubPemPath = prefix + "_public.pem";
    string pubDerPath = prefix + "_public.der";

    if (!force) {
        if (fileExists(privPemPath) || fileExists(privDerPath) ||
            fileExists(pubPemPath) || fileExists(pubDerPath)) {
            cerr << "Output file already exists (use --force to overwrite)" << endl;
            return RET_IO;
        }
    }

    {
        BioPtr bio(BIO_new_file(privPemPath.c_str(), "wb"));
        if (!bio || PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            cerr << "Failed to write " << privPemPath << endl;
            return RET_IO;
        }
    }
    {
        BioPtr bio(BIO_new_file(privDerPath.c_str(), "wb"));
        if (!bio || i2d_PKCS8PrivateKey_bio(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            cerr << "Failed to write " << privDerPath << endl;
            return RET_IO;
        }
    }
    {
        BioPtr bio(BIO_new_file(pubPemPath.c_str(), "wb"));
        if (!bio || PEM_write_bio_PUBKEY(bio.get(), key.get()) != 1) {
            cerr << "Failed to write " << pubPemPath << endl;
            return RET_IO;
        }
    }
    {
        BioPtr bio(BIO_new_file(pubDerPath.c_str(), "wb"));
        if (!bio || i2d_PUBKEY_bio(bio.get(), key.get()) != 1) {
            cerr << "Failed to write " << pubDerPath << endl;
            return RET_IO;
        }
    }

    return RET_OK;
}

int handleKeyInfo(int argc, char **argv) {
    string pubFile;
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--pub" || arg == "-pub") && i + 1 < argc) pubFile = argv[++i];
    }
    if (pubFile.empty()) {
        cerr << "Usage: lab03 key-info --pub <file>" << endl;
        return RET_USAGE;
    }

    if (!fileExists(pubFile)) {
        cerr << "File not found: " << pubFile << endl;
        return RET_IO;
    }

    EvpPkeyPtr key;
    string err;
    if (!loadStrictKey(pubFile, false, key, err)) {
        if (err == "explicit parameters") {
            cout << "Rejected: explicit parameters" << endl;
            return RET_DATA;
        }
        cerr << "Failed to load public key: " << err << endl;
        return RET_DATA;
    }

    string alg = getKeyAlgorithmName(key.get());
    string curve = getKeyCurveName(key.get());
    int secBits = getKeySecurityLevel(key.get());
    Bytes pubRep = getPublicKeyRepresentation(key.get());
    Bytes kid = computeSpkiKeyId(key.get());

    cout << "algorithm:      " << alg << endl;
    cout << "curve:          " << curve << endl;
    cout << "security level: " << secBits << " bit" << endl;
    cout << "public key:     " << toHex(pubRep, false) << endl;
    cout << "key ID:         " << toHex(kid, false) << endl;

    return RET_OK;
}

int handleKeyCheck(int argc, char **argv) {
    string privFile, pubFile;
    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--priv" || arg == "-priv") && i + 1 < argc) privFile = argv[++i];
        else if ((arg == "--pub" || arg == "-pub") && i + 1 < argc) pubFile = argv[++i];
    }
    if (privFile.empty() || pubFile.empty()) {
        cerr << "Usage: lab03 key-check --priv <file> --pub <file>" << endl;
        return RET_USAGE;
    }

    if (!fileExists(privFile) || !fileExists(pubFile)) {
        cerr << "File not found" << endl;
        return RET_IO;
    }

    EvpPkeyPtr privKey, pubKey;
    string err;
    if (!loadStrictKey(privFile, true, privKey, err)) {
        cerr << "Failed to load private key: " << err << endl;
        return RET_DATA;
    }
    if (!loadStrictKey(pubFile, false, pubKey, err)) {
        cerr << "Failed to load public key: " << err << endl;
        return RET_DATA;
    }

    if (EVP_PKEY_eq(privKey.get(), pubKey.get()) != 1) {
        cout << "MISMATCH" << endl;
        return RET_CRYPTO;
    }

    int type = EVP_PKEY_base_id(privKey.get());
    if (type == EVP_PKEY_EC) {
        BnPtr d = makeBn();
        BIGNUM *rawD = d.get();
        if (EVP_PKEY_get_bn_param(privKey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &rawD) != 1) {
            cerr << "Failed to extract private scalar d" << endl;
            return RET_INTERNAL;
        }

        char curveName[64] = {0};
        EVP_PKEY_get_utf8_string_param(privKey.get(), OSSL_PKEY_PARAM_GROUP_NAME, curveName, sizeof(curveName), nullptr);
        BnCtxPtr ctx = makeBnCtx();
        EcCurve curve;
        if (!loadNamedCurve(curveName, curve, ctx.get())) {
            cerr << "Failed to load curve parameters" << endl;
            return RET_INTERNAL;
        }

        EcPointPtr Q(EC_POINT_new(curve.grp.get()));
        EC_POINT_mul(curve.grp.get(), Q.get(), d.get(), nullptr, nullptr, ctx.get());

        uint8_t pubBuf[133] = {0};
        size_t pubLen = 0;
        EVP_PKEY_get_octet_string_param(pubKey.get(), OSSL_PKEY_PARAM_PUB_KEY, pubBuf, sizeof(pubBuf), &pubLen);

        EcPointPtr Q2(EC_POINT_new(curve.grp.get()));
        EC_POINT_oct2point(curve.grp.get(), Q2.get(), pubBuf, pubLen, ctx.get());

        if (EC_POINT_cmp(curve.grp.get(), Q.get(), Q2.get(), ctx.get()) != 0) {
            cout << "MISMATCH: Q != dG" << endl;
            return RET_CRYPTO;
        }
    }

    cout << "MATCH" << endl;
    return RET_OK;
}

int handlePubImport(int argc, char **argv) {
    string curveName;
    string pointHex;
    string outFile;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--curve" || arg == "-curve") && i + 1 < argc) curveName = argv[++i];
        else if ((arg == "--point" || arg == "-point") && i + 1 < argc) pointHex = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outFile = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (curveName.empty() || pointHex.empty() || outFile.empty()) {
        cerr << "Usage: lab03 pub-import --curve <name> -point <hex> -out <file> [--force]" << endl;
        return RET_USAGE;
    }

    if (!force && fileExists(outFile)) {
        cerr << "Output file exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    Bytes ptBytes;
    if (!fromHex(pointHex, ptBytes) || ptBytes.empty()) {
        cout << "Rejected: invalid hex" << endl;
        return RET_DATA;
    }

    string norm = normalizeAlgName(curveName);
    EvpPkeyPtr pubKey;

    if (norm == "P-256" || norm == "P-384" || norm == "secp256k1") {
        if (ptBytes.size() == 1 && ptBytes[0] == 0x00) {
            cout << "Rejected: identity point" << endl;
            return RET_DATA;
        }

        BnCtxPtr ctx = makeBnCtx();
        EcCurve curve;
        if (!loadNamedCurve(norm, curve, ctx.get())) {
            cout << "Rejected: unknown curve" << endl;
            return RET_USAGE;
        }

        EcAffinePoint pt = newAffinePoint();
        string err;
        if (!decodeSec1Point(curve, ptBytes, pt, err, ctx.get())) {
            cout << "Rejected: " << err << endl;
            return RET_DATA;
        }

        Bytes uncompressed = encodeSec1Point(curve, pt, false, ctx.get());

        ParamBldPtr bld(OSSL_PARAM_BLD_new());
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve.name.c_str(), 0);
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, uncompressed.data(), uncompressed.size());
        ParamPtr params(OSSL_PARAM_BLD_to_param(bld.get()));

        EvpPkeyCtxPtr fctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!fctx || EVP_PKEY_fromdata_init(fctx.get()) <= 0) {
            cout << "Rejected: fromdata init failed" << endl;
            return RET_INTERNAL;
        }

        EVP_PKEY *rawKey = nullptr;
        if (EVP_PKEY_fromdata(fctx.get(), &rawKey, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0 || !rawKey) {
            cout << "Rejected: fromdata failed" << endl;
            return RET_DATA;
        }
        pubKey.reset(rawKey);

        EvpPkeyCtxPtr vctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pubKey.get(), nullptr));
        if (EVP_PKEY_public_check(vctx.get()) <= 0) {
            cout << "Rejected: public check failed" << endl;
            return RET_DATA;
        }
    } else if (norm == "X25519") {
        if (ptBytes.size() != 32) {
            cout << "Rejected: X25519 public key must be 32 bytes" << endl;
            return RET_DATA;
        }
        bool allZero = true;
        for (uint8_t b : ptBytes) {
            if (b != 0) { allZero = false; break; }
        }
        if (allZero) {
            cout << "Rejected: all-zero low-order point" << endl;
            return RET_DATA;
        }

        EVP_PKEY *rawKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, ptBytes.data(), 32);
        if (!rawKey) {
            cout << "Rejected: invalid X25519 public key" << endl;
            return RET_DATA;
        }
        pubKey.reset(rawKey);
    } else if (norm == "Ed25519") {
        if (ptBytes.size() != 32) {
            cout << "Rejected: Ed25519 public key must be 32 bytes" << endl;
            return RET_DATA;
        }
        EVP_PKEY *rawKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, ptBytes.data(), 32);
        if (!rawKey) {
            cout << "Rejected: invalid Ed25519 public key" << endl;
            return RET_DATA;
        }
        pubKey.reset(rawKey);
    } else if (norm == "Ed448") {
        if (ptBytes.size() != 57) {
            cout << "Rejected: Ed448 public key must be 57 bytes" << endl;
            return RET_DATA;
        }
        EVP_PKEY *rawKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, ptBytes.data(), 57);
        if (!rawKey) {
            cout << "Rejected: invalid Ed448 public key" << endl;
            return RET_DATA;
        }
        pubKey.reset(rawKey);
    } else {
        cout << "Rejected: unsupported curve" << endl;
        return RET_USAGE;
    }

    bool isDer = (outFile.size() >= 4 && outFile.substr(outFile.size() - 4) == ".der");
    BioPtr bio(BIO_new_file(outFile.c_str(), "wb"));
    if (!bio) {
        cerr << "Failed to open output file: " << outFile << endl;
        return RET_IO;
    }

    if (isDer) {
        if (i2d_PUBKEY_bio(bio.get(), pubKey.get()) != 1) {
            cerr << "Failed to write DER public key" << endl;
            return RET_IO;
        }
    } else {
        if (PEM_write_bio_PUBKEY(bio.get(), pubKey.get()) != 1) {
            cerr << "Failed to write PEM public key" << endl;
            return RET_IO;
        }
    }

    return RET_OK;
}
