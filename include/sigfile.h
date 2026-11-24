#pragma once

#include "common.h"

constexpr uint8_t ALG_RSA_PKCS1_SHA256 = 0x01;
constexpr uint8_t ALG_RSA_PSS_SHA256 = 0x02;
constexpr uint8_t ALG_ECDSA_P256_SHA256 = 0x11;
constexpr uint8_t ALG_ECDSA_P384_SHA384 = 0x12;
constexpr uint8_t ALG_ECDSA_SECP256K1_SHA256 = 0x13;
constexpr uint8_t ALG_ED25519 = 0x21;
constexpr uint8_t ALG_ED448 = 0x22;

struct L3sgContainer {
    uint8_t version;
    uint8_t alg;
    uint16_t reserved;
    Bytes keyId;
    uint16_t sigLen;
    Bytes signature;
};

bool parseAlgName(const string &name, uint8_t &algId);
string getAlgNameFromId(uint8_t algId);
bool isKeyTypeMatchingAlg(EVP_PKEY *key, uint8_t algId);

Bytes buildL3sgTbs(uint8_t version, uint8_t alg, uint16_t reserved, const Bytes &keyId, const Bytes &fileSha512);
Bytes serializeL3sgContainer(const L3sgContainer &container);
bool parseL3sgContainer(const Bytes &data, L3sgContainer &container, string &errReason);

int handleSign(int argc, char **argv);
int handleVerify(int argc, char **argv);
