#pragma once

#include "common.h"
#include "ec_math.h"

BnPtr ecdsaBits2Int(const EcCurve &curve, const Bytes &hash);

void ecdsaSignByHand(const EcCurve &curve, const BIGNUM *d, const Bytes &hash,
                     const BIGNUM *k, BIGNUM *r, BIGNUM *s, BN_CTX *ctx);

bool ecdsaVerifyByHand(const EcCurve &curve, const EC_POINT *Q, const Bytes &hash,
                       const BIGNUM *r, const BIGNUM *s, BN_CTX *ctx);

BnPtr rfc6979Nonce(const EcCurve &curve, const BIGNUM *d, const Bytes &hash);

Bytes encodeEcdsaDer(const BIGNUM *r, const BIGNUM *s);
bool decodeEcdsaDer(const Bytes &der, BIGNUM *r, BIGNUM *s);

bool ecdsaEvpSign(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, Bytes &outDerSig);
bool ecdsaEvpVerify(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, const Bytes &derSig, bool strict, string &warnOrErr);

int handleEcdsaDemo(int argc, char **argv);
int handleEcdsaRecover(int argc, char **argv);
