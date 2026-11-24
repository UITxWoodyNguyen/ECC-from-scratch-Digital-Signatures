#pragma once

#include "common.h"

struct EdCurveContext {
    BnPtr p;
    BnPtr d;
    BnPtr L;
    BnCtxPtr ctx;
};

struct EdPoint {
    BnPtr x;
    BnPtr y;
};

EdPoint newEdPoint();
EdPoint copyEdPoint(const EdPoint &pt);
void edPointAdd(const EdCurveContext &E, EdPoint &R, const EdPoint &P, const EdPoint &Q);
void edPointMul(const EdCurveContext &E, EdPoint &R, const BIGNUM *k, const EdPoint &P);

Bytes edEncodePoint(const EdPoint &P);
bool edDecodePoint(const EdCurveContext &E, const Bytes &in, EdPoint &P);

bool eddsaEvpSign(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, Bytes &outSig);
bool eddsaEvpVerify(EVP_PKEY *key, uint8_t algId, const Bytes &tbs, const Bytes &sig);

int handleEd25519Demo();
int handleSigBench(int argc, char **argv);
