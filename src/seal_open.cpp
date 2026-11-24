#include "seal_open.h"
#include "sigfile.h"
#include "ec_keys.h"
#include "rsa_sig.h"
#include "ecdsa.h"
#include "eddsa.h"
#include "ecies.h"

int handleSeal(int argc, char **argv) {
    string signKeyPath, toPubPath, inFilePath, outPkgPath;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--sign-key" || arg == "-sign-key") && i + 1 < argc) signKeyPath = argv[++i];
        else if ((arg == "--to" || arg == "-to") && i + 1 < argc) toPubPath = argv[++i];
        else if ((arg == "--in" || arg == "-in") && i + 1 < argc) inFilePath = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outPkgPath = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (signKeyPath.empty() || toPubPath.empty() || inFilePath.empty() || outPkgPath.empty()) {
        cerr << "Usage: lab03 seal --sign-key <priv> --to <pub> -in <file> -out <pkg> [--force]" << endl;
        return RET_USAGE;
    }

    if (!fileExists(inFilePath)) {
        cerr << "File not found: " << inFilePath << endl;
        return RET_IO;
    }

    if (!force && fileExists(outPkgPath)) {
        cerr << "Output exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    string tmpSigPath = outPkgPath + ".tmp_sig";
    string tmpPayloadPath = outPkgPath + ".tmp_payload";

    char *signArgs[] = {
        argv[0],
        const_cast<char *>("sign"),
        const_cast<char *>("--alg"),
        nullptr,
        const_cast<char *>("--priv"),
        const_cast<char *>(signKeyPath.c_str()),
        const_cast<char *>("-in"),
        const_cast<char *>(inFilePath.c_str()),
        const_cast<char *>("-out"),
        const_cast<char *>(tmpSigPath.c_str()),
        const_cast<char *>("--force")
    };

    EvpPkeyPtr signerKey;
    string err;
    if (!loadStrictKey(signKeyPath, true, signerKey, err)) {
        cerr << "Failed to load signer key" << endl;
        return RET_DATA;
    }
    int sType = EVP_PKEY_base_id(signerKey.get());
    string algName;
    if (sType == EVP_PKEY_RSA || sType == EVP_PKEY_RSA_PSS) algName = "rsa-pss-sha256";
    else if (sType == EVP_PKEY_EC) {
        char cName[64] = {0};
        EVP_PKEY_get_utf8_string_param(signerKey.get(), OSSL_PKEY_PARAM_GROUP_NAME, cName, sizeof(cName), nullptr);
        string c(cName);
        if (c == "secp384r1" || c == "P-384") algName = "ecdsa-p384-sha384";
        else if (c == "secp256k1") algName = "ecdsa-secp256k1-sha256";
        else algName = "ecdsa-p256-sha256";
    } else if (sType == EVP_PKEY_ED25519) algName = "ed25519";
    else if (sType == EVP_PKEY_ED448) algName = "ed448";
    else {
        cerr << "Unsupported signer key type" << endl;
        return RET_DATA;
    }

    signArgs[3] = const_cast<char *>(algName.c_str());
    int ret = handleSign(11, signArgs);
    if (ret != RET_OK) {
        removeFile(tmpSigPath);
        return ret;
    }

    Bytes sigData, fileData;
    readFileBytes(tmpSigPath, sigData);
    readFileBytes(inFilePath, fileData);
    removeFile(tmpSigPath);

    Bytes payload;
    uint32_t sigSize = static_cast<uint32_t>(sigData.size());
    payload.pb(static_cast<uint8_t>((sigSize >> 24) & 0xFF));
    payload.pb(static_cast<uint8_t>((sigSize >> 16) & 0xFF));
    payload.pb(static_cast<uint8_t>((sigSize >> 8) & 0xFF));
    payload.pb(static_cast<uint8_t>(sigSize & 0xFF));
    payload.insert(payload.end(), all(sigData));
    payload.insert(payload.end(), all(fileData));

    writeFileBytes(tmpPayloadPath, payload, true);

    char *encArgs[] = {
        argv[0],
        const_cast<char *>("ecies-encrypt"),
        const_cast<char *>("--pub"),
        const_cast<char *>(toPubPath.c_str()),
        const_cast<char *>("-in"),
        const_cast<char *>(tmpPayloadPath.c_str()),
        const_cast<char *>("-out"),
        const_cast<char *>(outPkgPath.c_str()),
        const_cast<char *>("--force")
    };
    ret = handleEciesEncrypt(9, encArgs);
    removeFile(tmpPayloadPath);
    return ret;
}

int handleOpen(int argc, char **argv) {
    string privKeyPath, fromPubPath, inPkgPath, outFilePath;
    bool force = false;

    FOR(i, 2, argc - 1) {
        string arg = argv[i];
        if ((arg == "--priv" || arg == "-priv") && i + 1 < argc) privKeyPath = argv[++i];
        else if ((arg == "--from" || arg == "-from") && i + 1 < argc) fromPubPath = argv[++i];
        else if ((arg == "--in" || arg == "-in") && i + 1 < argc) inPkgPath = argv[++i];
        else if ((arg == "--out" || arg == "-out") && i + 1 < argc) outFilePath = argv[++i];
        else if (arg == "--force" || arg == "-f" || arg == "-force") force = true;
    }

    if (privKeyPath.empty() || fromPubPath.empty() || inPkgPath.empty() || outFilePath.empty()) {
        cerr << "Usage: lab03 open --priv <priv> --from <pub> -in <pkg> -out <file> [--force]" << endl;
        return RET_USAGE;
    }

    if (!fileExists(inPkgPath)) {
        cerr << "Package not found: " << inPkgPath << endl;
        return RET_IO;
    }

    if (!force && fileExists(outFilePath)) {
        cerr << "Output exists (use --force to overwrite)" << endl;
        return RET_IO;
    }

    string tmpPayloadPath = outFilePath + ".tmp_dec";
    char *decArgs[] = {
        argv[0],
        const_cast<char *>("ecies-decrypt"),
        const_cast<char *>("--priv"),
        const_cast<char *>(privKeyPath.c_str()),
        const_cast<char *>("-in"),
        const_cast<char *>(inPkgPath.c_str()),
        const_cast<char *>("-out"),
        const_cast<char *>(tmpPayloadPath.c_str()),
        const_cast<char *>("--force")
    };

    int ret = handleEciesDecrypt(9, decArgs);
    if (ret != RET_OK) {
        removeFile(tmpPayloadPath);
        return ret;
    }

    Bytes payload;
    if (!readFileBytes(tmpPayloadPath, payload) || payload.size() < 4) {
        removeFile(tmpPayloadPath);
        cout << "INVALID" << endl;
        return RET_CRYPTO;
    }
    removeFile(tmpPayloadPath);

    uint32_t sigSize = 0;
    REP(i, 0, 4) {
        sigSize = (sigSize << 8) | payload[i];
    }
    if (payload.size() < 4 + sigSize) {
        cout << "INVALID" << endl;
        return RET_CRYPTO;
    }

    Bytes sigData(payload.begin() + 4, payload.begin() + 4 + sigSize);
    Bytes fileData(payload.begin() + 4 + sigSize, payload.end());

    string tmpSigPath = outFilePath + ".tmp_sig";
    string tmpFilePath = outFilePath + ".tmp_file";
    writeFileBytes(tmpSigPath, sigData, true);
    writeFileBytes(tmpFilePath, fileData, true);

    char *verArgs[] = {
        argv[0],
        const_cast<char *>("verify"),
        const_cast<char *>("--pub"),
        const_cast<char *>(fromPubPath.c_str()),
        const_cast<char *>("-in"),
        const_cast<char *>(tmpFilePath.c_str()),
        const_cast<char *>("-sig"),
        const_cast<char *>(tmpSigPath.c_str())
    };

    ret = handleVerify(8, verArgs);
    removeFile(tmpSigPath);

    if (ret == RET_OK) {
        renameFile(tmpFilePath, outFilePath);
        return RET_OK;
    } else {
        removeFile(tmpFilePath);
        return ret;
    }
}
