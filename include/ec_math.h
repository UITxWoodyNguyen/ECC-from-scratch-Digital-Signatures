#pragma once

#include "common.h"

struct EcCurve {
    int nid;
    string name;
    BnPtr p;
    BnPtr a;
    BnPtr b;
    BnPtr n;
    size_t fieldBytes;
    EcPointPtr G;
    EcGroupPtr grp;
};

struct EcAffinePoint {
    BnPtr x;
    BnPtr y;
    bool isInf;
};

bool loadNamedCurve(const string &name, EcCurve &curve, BN_CTX *ctx);

EcAffinePoint newAffinePoint();
EcAffinePoint copyAffinePoint(const EcAffinePoint &pt);

bool isPointOnCurve(const EcCurve &curve, const EcAffinePoint &pt, BN_CTX *ctx);
void ecPointAdd(const EcCurve &curve, EcAffinePoint &res, const EcAffinePoint &P, const EcAffinePoint &Q, BN_CTX *ctx);
void ecPointDbl(const EcCurve &curve, EcAffinePoint &res, const EcAffinePoint &P, BN_CTX *ctx);
void ecPointMul(const EcCurve &curve, EcAffinePoint &res, const BIGNUM *k, const EcAffinePoint &P, BN_CTX *ctx);

bool decodeSec1Point(const EcCurve &curve, const Bytes &sec1, EcAffinePoint &pt, string &errReason, BN_CTX *ctx);
Bytes encodeSec1Point(const EcCurve &curve, const EcAffinePoint &pt, bool compressed, BN_CTX *ctx);

EcAffinePoint fromOpenSslPoint(const EC_GROUP *grp, const EC_POINT *pt, BN_CTX *ctx);
EC_POINT *toOpenSslPoint(const EC_GROUP *grp, const EcAffinePoint &pt, BN_CTX *ctx);
bool compareAffinePoints(const EcAffinePoint &P1, const EcAffinePoint &P2);

int handleEcAdd(int argc, char **argv);
int handleEcDbl(int argc, char **argv);
int handleEcMul(int argc, char **argv);
int handleEcValidate(int argc, char **argv);
int handleEcEncode(int argc, char **argv);
int handleEcInvalidCurveDemo();
