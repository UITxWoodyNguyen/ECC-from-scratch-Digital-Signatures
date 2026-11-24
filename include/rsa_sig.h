#pragma once

#include "common.h"

Bytes mgf1Sha256(const Bytes &seed, size_t maskLen);
Bytes rsaPrimitive(const Bytes &msgBytes, const BIGNUM *exp, const BIGNUM *n, BN_CTX *ctx);

Bytes emsaPkcs1v15Encode(const Bytes &mHash, size_t k);
Bytes emsaPssEncode(const Bytes &mHash, size_t emBits, size_t sLen);
bool emsaPssVerify(const Bytes &mHash, const Bytes &EMin, size_t emBits, size_t sLen);

bool rsaEvpSign(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, Bytes &outSig);
bool rsaEvpVerify(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, const Bytes &sig);

int handleRsaSigDemo();
