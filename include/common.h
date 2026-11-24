#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <chrono>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

using namespace std;

#define ll int64_t
#define pii pair<int, int>
#define pll pair<ll, ll>
#define FOR(i, a, b) for (int i = a, _b = (b); i <= _b; ++i)
#define REP(i, a, b) for (int i = a, _b = (b); i < _b; ++i)
#define FORD(i, b, a) for (int i = (b), _a = (a); i >= _a; --i)
#define all(x) (x).begin(), (x).end()
#define allr(x) (x).rbegin(), (x).rend()
#define X first
#define Y second
#define pb push_back
#define eb emplace_back

constexpr int RET_OK = 0;
constexpr int RET_USAGE = 1;
constexpr int RET_IO = 2;
constexpr int RET_DATA = 3;
constexpr int RET_CRYPTO = 4;
constexpr int RET_INTERNAL = 5;

using Bytes = vector<uint8_t>;

struct BnDeleter {
    void operator()(BIGNUM *ptr) const {
        if (ptr) BN_free(ptr);
    }
};

struct BnClearDeleter {
    void operator()(BIGNUM *ptr) const {
        if (ptr) BN_clear_free(ptr);
    }
};

struct BnCtxDeleter {
    void operator()(BN_CTX *ptr) const {
        if (ptr) BN_CTX_free(ptr);
    }
};

struct EcGroupDeleter {
    void operator()(EC_GROUP *ptr) const {
        if (ptr) EC_GROUP_free(ptr);
    }
};

struct EcPointDeleter {
    void operator()(EC_POINT *ptr) const {
        if (ptr) EC_POINT_free(ptr);
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY *ptr) const {
        if (ptr) EVP_PKEY_free(ptr);
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *ptr) const {
        if (ptr) EVP_PKEY_CTX_free(ptr);
    }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX *ptr) const {
        if (ptr) EVP_MD_CTX_free(ptr);
    }
};

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ptr) const {
        if (ptr) EVP_CIPHER_CTX_free(ptr);
    }
};

struct EcdsaSigDeleter {
    void operator()(ECDSA_SIG *ptr) const {
        if (ptr) ECDSA_SIG_free(ptr);
    }
};

struct BioDeleter {
    void operator()(BIO *ptr) const {
        if (ptr) BIO_free(ptr);
    }
};

struct ParamBldDeleter {
    void operator()(OSSL_PARAM_BLD *ptr) const {
        if (ptr) OSSL_PARAM_BLD_free(ptr);
    }
};

struct ParamDeleter {
    void operator()(OSSL_PARAM *ptr) const {
        if (ptr) OSSL_PARAM_free(ptr);
    }
};

using BnPtr = unique_ptr<BIGNUM, BnDeleter>;
using BnClearPtr = unique_ptr<BIGNUM, BnClearDeleter>;
using BnCtxPtr = unique_ptr<BN_CTX, BnCtxDeleter>;
using EcGroupPtr = unique_ptr<EC_GROUP, EcGroupDeleter>;
using EcPointPtr = unique_ptr<EC_POINT, EcPointDeleter>;
using EvpPkeyPtr = unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr = unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpCipherCtxPtr = unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using EcdsaSigPtr = unique_ptr<ECDSA_SIG, EcdsaSigDeleter>;
using BioPtr = unique_ptr<BIO, BioDeleter>;
using ParamBldPtr = unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter>;
using ParamPtr = unique_ptr<OSSL_PARAM, ParamDeleter>;

BnPtr makeBn();
BnClearPtr makeBnClear();
BnCtxPtr makeBnCtx();

string toHex(const uint8_t *data, size_t len, bool uppercase = false);
string toHex(const Bytes &bytes, bool uppercase = false);
bool fromHex(const string &hexStr, Bytes &out);
Bytes fromHex(const string &hexStr);

bool fileExists(const string &path);
bool isDirectory(const string &path);
bool createDirectories(const string &dirPath);
bool readFileBytes(const string &path, Bytes &out);
bool writeFileBytes(const string &path, const Bytes &data, bool force = false);
bool writePrivateFileBytes(const string &path, const Bytes &data, bool force = false);
bool removeFile(const string &path);
bool renameFile(const string &src, const string &dst);

void secureCleanse(void *ptr, size_t len);
void secureCleanse(Bytes &b);

Bytes sha256(const Bytes &data);
Bytes sha512(const Bytes &data);
Bytes sha512StreamFile(const string &filePath, bool &ok);

Bytes computeSpkiKeyId(EVP_PKEY *key);
