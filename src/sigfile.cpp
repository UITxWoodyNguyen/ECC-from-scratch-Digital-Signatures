#include "sigfile.h"
#include "ec_keys.h"
#include "rsa_sig.h"
#include "ecdsa.h"
#include "eddsa.h"

bool parseAlgName(const string &name, uint8_t &algId) {
    if (name == "rsa-pkcs1-sha256") {
        algId = ALG_RSA_PKCS1_SHA256;
        return true;
    }
    if (name == "rsa-pss-sha256") {
        algId = ALG_RSA_PSS_SHA256;
        return true;
    }
    if (name == "ecdsa-p256-sha256") {
        algId = ALG_ECDSA_P256_SHA256;
        return true;
    }
    if (name == "ecdsa-p384-sha384") {
        algId = ALG_ECDSA_P384_SHA384;
        return true;
    }
    if (name == "ecdsa-secp256k1-sha256") {
        algId = ALG_ECDSA_SECP256K1_SHA256;
        return true;
    }
    if (name == "ed25519" || name == "Ed25519") {
        algId = ALG_ED25519;
        return true;
    }
    if (name == "ed448" || name == "Ed448") {
        algId = ALG_ED448;
        return true;
    }
    return false;
}

string getAlgNameFromId(uint8_t algId) {
    switch (algId) {
        case ALG_RSA_PKCS1_SHA256: return "rsa-pkcs1-sha256";
        case ALG_RSA_PSS_SHA256: return "rsa-pss-sha256";
        case ALG_ECDSA_P256_SHA256: return "ecdsa-p256-sha256";
        case ALG_ECDSA_P384_SHA384: return "ecdsa-p384-sha384";
        case ALG_ECDSA_SECP256K1_SHA256: return "ecdsa-secp256k1-sha256";
        case ALG_ED25519: return "ed25519";
        case ALG_ED448: return "ed448";
        default: return "unknown";
    }
}

bool isKeyTypeMatchingAlg(EVP_PKEY *key, uint8_t algId) {
    if (!key) return false;
    int type = EVP_PKEY_base_id(key);

    if (algId == ALG_RSA_PKCS1_SHA256 || algId == ALG_RSA_PSS_SHA256) {
        if (type != EVP_PKEY_RSA && type != EVP_PKEY_RSA_PSS) return false;
        return (EVP_PKEY_get_bits(key) >= 2048);
    }
    if (algId == ALG_ECDSA_P256_SHA256) {
        if (type != EVP_PKEY_EC) return false;
        char cName[64] = {0};
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, cName, sizeof(cName), nullptr);
        string c(cName);
        return (c == "prime256v1" || c == "P-256" || c == "secp256r1");
    }
    if (algId == ALG_ECDSA_P384_SHA384) {
        if (type != EVP_PKEY_EC) return false;
        char cName[64] = {0};
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, cName, sizeof(cName), nullptr);
        string c(cName);
        return (c == "secp384r1" || c == "P-384");
    }
    if (algId == ALG_ECDSA_SECP256K1_SHA256) {
        if (type != EVP_PKEY_EC) return false;
        char cName[64] = {0};
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, cName, sizeof(cName), nullptr);
        string c(cName);
        return (c == "secp256k1");
    }
    if (algId == ALG_ED25519) {
        return (type == EVP_PKEY_ED25519);
    }
    if (algId == ALG_ED448) {
        return (type == EVP_PKEY_ED448);
    }
    return false;
}

Bytes buildL3sgTbs(uint8_t version, uint8_t alg, uint16_t reserved, const Bytes &keyId, const Bytes &fileSha512) {
    static const char label[] = "LAB03-SIG-v1";
    Bytes tbs;
    tbs.reserve(113);
    tbs.insert(tbs.end(), label, label + 12);
    tbs.pb(0x00);
    tbs.pb(version);
    tbs.pb(alg);
    tbs.pb(static_cast<uint8_t>(reserved >> 8));
    tbs.pb(static_cast<uint8_t>(reserved & 0xFF));
    tbs.insert(tbs.end(), all(keyId));
    tbs.insert(tbs.end(), all(fileSha512));
    return tbs;
}

Bytes serializeL3sgContainer(const L3sgContainer &c) {
    Bytes out;
    out.reserve(42 + c.sigLen);
    out.pb('L'); out.pb('3'); out.pb('S'); out.pb('G');
    out.pb(c.version);
    out.pb(c.alg);
    out.pb(static_cast<uint8_t>(c.reserved >> 8));
    out.pb(static_cast<uint8_t>(c.reserved & 0xFF));
    out.insert(out.end(), all(c.keyId));
    out.pb(static_cast<uint8_t>(c.sigLen >> 8));
    out.pb(static_cast<uint8_t>(c.sigLen & 0xFF));
    out.insert(out.end(), all(c.signature));
    return out;
}

bool parseL3sgContainer(const Bytes &data, L3sgContainer &c, string &errReason) {
    if (data.size() < 42) {
        errReason = "container truncated (less than 42 bytes)";
        return false;
    }
    if (memcmp(data.data(), "L3SG", 4) != 0) {
        errReason = "invalid magic";
        return false;
    }
    c.version = data[4];
    if (c.version != 0x01) {
        errReason = "unsupported version";
        return false;
    }
    c.alg = data[5];
    string algName = getAlgNameFromId(c.alg);
    if (algName == "unknown") {
        errReason = "unknown algorithm ID";
        return false;
    }
    c.reserved = static_cast<uint16_t>((data[6] << 8) | data[7]);
    if (c.reserved != 0x0000) {
        errReason = "nonzero reserved field";
        return false;
    }
    c.keyId.assign(data.begin() + 8, data.begin() + 40);
    c.sigLen = static_cast<uint16_t>((data[40] << 8) | data[41]);
    if (data.size() != 42 + static_cast<size_t>(c.sigLen)) {
        errReason = "container size mismatch";
        return false;
    }
    c.signature.assign(data.begin() + 42, data.end());
    return true;
}

int handleSign(int argc, char **argv) {
    string algStr, privPath, inFilePath, outSigPath;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--alg" || arg == "-alg") && i + 1 < argc) algStr = argv[++i];
        else if ((arg == "--priv" || arg == "-priv") && i + 1 < argc) privPath = argv[++i];
        else if ((arg == "--in" || arg == "-in") && i + 1 < argc) inFilePath = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outSigPath = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (algStr.empty() || privPath.empty() || inFilePath.empty() || outSigPath.empty()) {
        cerr << "Usage: lab03 sign --alg <name> --priv <key> -in <file> -out <sig> [--force]" << endl;
        return RET_USAGE;
    }

    if (!fileExists(inFilePath)) {
        cerr << "Input file not found: " << inFilePath << endl;
        return RET_IO;
    }

    if (!force && fileExists(outSigPath)) {
        cerr << "Output file exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    uint8_t algId = 0;
    if (!parseAlgName(algStr, algId)) {
        cerr << "Unknown algorithm: " << algStr << endl;
        return RET_USAGE;
    }

    EvpPkeyPtr privKey;
    string err;
    if (!loadStrictKey(privPath, true, privKey, err)) {
        cerr << "Failed to load private key: " << err << endl;
        return RET_DATA;
    }

    if (!isKeyTypeMatchingAlg(privKey.get(), algId)) {
        cerr << "Key type does not match algorithm: " << algStr << endl;
        return RET_DATA;
    }

    Bytes keyId = computeSpkiKeyId(privKey.get());
    if (keyId.size() != 32) {
        cerr << "Failed to compute key ID" << endl;
        return RET_INTERNAL;
    }

    bool hashOk = false;
    Bytes fileSha = sha512StreamFile(inFilePath, hashOk);
    if (!hashOk) {
        cerr << "Failed to hash input file" << endl;
        return RET_IO;
    }

    Bytes tbs = buildL3sgTbs(0x01, algId, 0x0000, keyId, fileSha);

    Bytes signature;
    bool signOk = false;
    if (algId == ALG_RSA_PKCS1_SHA256 || algId == ALG_RSA_PSS_SHA256) {
        signOk = rsaEvpSign(privKey.get(), algId, tbs, signature);
    } else if (algId == ALG_ECDSA_P256_SHA256 || algId == ALG_ECDSA_P384_SHA384 || algId == ALG_ECDSA_SECP256K1_SHA256) {
        signOk = ecdsaEvpSign(privKey.get(), algId, tbs, signature);
    } else if (algId == ALG_ED25519 || algId == ALG_ED448) {
        signOk = eddsaEvpSign(privKey.get(), algId, tbs, signature);
    }

    if (!signOk || signature.empty()) {
        cerr << "Signing failed" << endl;
        return RET_CRYPTO;
    }

    L3sgContainer container;
    container.version = 0x01;
    container.alg = algId;
    container.reserved = 0x0000;
    container.keyId = keyId;
    container.sigLen = static_cast<uint16_t>(signature.size());
    container.signature = signature;

    Bytes contBytes = serializeL3sgContainer(container);
    if (!writeFileBytes(outSigPath, contBytes, force)) {
        cerr << "Failed to write signature file" << endl;
        return RET_IO;
    }

    return RET_OK;
}

int handleVerify(int argc, char **argv) {
    string pubPath, inFilePath, sigPath;
    bool strict = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--pub" || arg == "-pub") && i + 1 < argc) pubPath = argv[++i];
        else if ((arg == "--in" || arg == "-in") && i + 1 < argc) inFilePath = argv[++i];
        else if ((arg == "--sig" || arg == "-sig") && i + 1 < argc) sigPath = argv[++i];
        else if (arg == "--strict" || arg == "-strict") strict = true;
    }

    if (pubPath.empty() || inFilePath.empty() || sigPath.empty()) {
        cerr << "Usage: lab03 verify --pub <key> -in <file> -sig <sig> [--strict]" << endl;
        return RET_USAGE;
    }

    if (!fileExists(inFilePath) || !fileExists(sigPath)) {
        cerr << "Missing file" << endl;
        return RET_IO;
    }

    Bytes sigFileData;
    if (!readFileBytes(sigPath, sigFileData)) {
        cerr << "Failed to read signature file" << endl;
        return RET_IO;
    }

    L3sgContainer container;
    string parseErr;
    if (!parseL3sgContainer(sigFileData, container, parseErr)) {
        cerr << "Format error: " << parseErr << endl;
        return RET_DATA;
    }

    EvpPkeyPtr pubKey;
    string err;
    if (!loadStrictKey(pubPath, false, pubKey, err)) {
        cerr << "Failed to load public key: " << err << endl;
        return RET_DATA;
    }

    if (!isKeyTypeMatchingAlg(pubKey.get(), container.alg)) {
        cout << "INVALID" << endl;
        cerr << "Key type mismatch with container algorithm" << endl;
        return RET_DATA;
    }

    Bytes actualKeyId = computeSpkiKeyId(pubKey.get());
    if (actualKeyId != container.keyId) {
        cout << "INVALID" << endl;
        cerr << "Key ID mismatch" << endl;
        return RET_CRYPTO;
    }

    bool hashOk = false;
    Bytes fileSha = sha512StreamFile(inFilePath, hashOk);
    if (!hashOk) {
        cerr << "Failed to hash input file" << endl;
        return RET_IO;
    }

    Bytes tbs = buildL3sgTbs(container.version, container.alg, container.reserved, container.keyId, fileSha);

    bool verifyOk = false;
    string warnOrErr;

    if (container.alg == ALG_RSA_PKCS1_SHA256 || container.alg == ALG_RSA_PSS_SHA256) {
        verifyOk = rsaEvpVerify(pubKey.get(), container.alg, tbs, container.signature);
    } else if (container.alg == ALG_ECDSA_P256_SHA256 || container.alg == ALG_ECDSA_P384_SHA384 || container.alg == ALG_ECDSA_SECP256K1_SHA256) {
        verifyOk = ecdsaEvpVerify(pubKey.get(), container.alg, tbs, container.signature, strict, warnOrErr);
        if (!warnOrErr.empty()) {
            cerr << warnOrErr << endl;
        }
    } else if (container.alg == ALG_ED25519 || container.alg == ALG_ED448) {
        verifyOk = eddsaEvpVerify(pubKey.get(), container.alg, tbs, container.signature);
    }

    if (verifyOk) {
        cout << "VALID" << endl;
        return RET_OK;
    } else {
        cout << "INVALID" << endl;
        return RET_CRYPTO;
    }
}
