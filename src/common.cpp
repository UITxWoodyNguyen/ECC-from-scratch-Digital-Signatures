#include "common.h"
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define mkdir_compat(dir) _mkdir(dir)
#else
#include <unistd.h>
#define mkdir_compat(dir) mkdir(dir, 0755)
#endif

BnPtr makeBn() {
    BIGNUM *bn = BN_new();
    return BnPtr(bn);
}

BnClearPtr makeBnClear() {
    BIGNUM *bn = BN_new();
    return BnClearPtr(bn);
}

BnCtxPtr makeBnCtx() {
    BN_CTX *ctx = BN_CTX_new();
    return BnCtxPtr(ctx);
}

string toHex(const uint8_t *data, size_t len, bool uppercase) {
    static const char hexCharsLower[] = "0123456789abcdef";
    static const char hexCharsUpper[] = "0123456789ABCDEF";
    const char *hexTable = uppercase ? hexCharsUpper : hexCharsLower;
    string res;
    res.reserve(len * 2);
    REP(i, 0, len) {
        uint8_t b = data[i];
        res.pb(hexTable[(b >> 4) & 0x0F]);
        res.pb(hexTable[b & 0x0F]);
    }
    return res;
}

string toHex(const Bytes &bytes, bool uppercase) {
    return toHex(bytes.data(), bytes.size(), uppercase);
}

bool fromHex(const string &hexStr, Bytes &out) {
    out.clear();
    string cleaned;
    REP(i, 0, hexStr.size()) {
        char c = hexStr[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':') continue;
        cleaned.pb(c);
    }
    if (cleaned.size() % 2 != 0) return false;
    out.reserve(cleaned.size() / 2);
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexVal(cleaned[i]);
        int lo = hexVal(cleaned[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.pb(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

Bytes fromHex(const string &hexStr) {
    Bytes out;
    fromHex(hexStr, out);
    return out;
}

bool fileExists(const string &path) {
    struct stat st;
    return (stat(path.c_str(), &st) == 0);
}

bool isDirectory(const string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IFDIR) != 0;
}

bool createDirectories(const string &dirPath) {
    if (dirPath.empty() || dirPath == "." || dirPath == "/") return true;
    if (isDirectory(dirPath)) return true;

    string cur;
    for (size_t i = 0; i < dirPath.size(); ++i) {
        char c = dirPath[i];
        cur.pb(c);
        if (c == '/' || c == '\\' || i == dirPath.size() - 1) {
            if (cur == "/" || cur == "\\" || (cur.size() == 3 && cur[1] == ':')) continue;
            if (!isDirectory(cur)) {
                mkdir_compat(cur.c_str());
            }
        }
    }
    return isDirectory(dirPath);
}

bool readFileBytes(const string &path, Bytes &out) {
    ifstream f(path, ios::binary | ios::ate);
    if (!f.is_open()) return false;
    streamsize size = f.tellg();
    f.seekg(0, ios::beg);
    out.resize(static_cast<size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char *>(out.data()), size)) {
        out.clear();
        return false;
    }
    return true;
}

bool writeFileBytes(const string &path, const Bytes &data, bool force) {
    if (!force && fileExists(path)) return false;
    ofstream f(path, ios::binary | ios::trunc);
    if (!f.is_open()) return false;
    if (!data.empty()) {
        f.write(reinterpret_cast<const char *>(data.data()), data.size());
    }
    return f.good();
}

bool writePrivateFileBytes(const string &path, const Bytes &data, bool force) {
    if (!force && fileExists(path)) return false;
#ifndef _WIN32
    FILE *fp = fopen(path.c_str(), "wb");
    if (!fp) return false;
    chmod(path.c_str(), 0600);
    if (!data.empty()) {
        fwrite(data.data(), 1, data.size(), fp);
    }
    fclose(fp);
    return true;
#else
    return writeFileBytes(path, data, force);
#endif
}

bool removeFile(const string &path) {
    return (remove(path.c_str()) == 0);
}

bool renameFile(const string &src, const string &dst) {
    return (rename(src.c_str(), dst.c_str()) == 0);
}

void secureCleanse(void *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

void secureCleanse(Bytes &b) {
    if (!b.empty()) {
        OPENSSL_cleanse(b.data(), b.size());
    }
}

Bytes sha256(const Bytes &data) {
    Bytes digest(32);
    unsigned int outLen = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &outLen, EVP_sha256(), nullptr);
    return digest;
}

Bytes sha512(const Bytes &data) {
    Bytes digest(64);
    unsigned int outLen = 0;
    EVP_Digest(data.data(), data.size(), digest.data(), &outLen, EVP_sha512(), nullptr);
    return digest;
}

Bytes sha512StreamFile(const string &filePath, bool &ok) {
    ok = false;
    Bytes digest(64);
    ifstream f(filePath, ios::binary);
    if (!f.is_open()) return digest;

    EvpMdCtxPtr md(EVP_MD_CTX_new());
    if (!md || EVP_DigestInit_ex(md.get(), EVP_sha512(), nullptr) != 1) return digest;

    constexpr size_t BUF_SIZE = 64 * 1024;
    vector<char> buf(BUF_SIZE);
    while (f.read(buf.data(), BUF_SIZE) || f.gcount() > 0) {
        streamsize bytesRead = f.gcount();
        if (EVP_DigestUpdate(md.get(), buf.data(), static_cast<size_t>(bytesRead)) != 1) {
            return digest;
        }
    }
    unsigned int outLen = 0;
    if (EVP_DigestFinal_ex(md.get(), digest.data(), &outLen) == 1 && outLen == 64) {
        ok = true;
    }
    return digest;
}

Bytes computeSpkiKeyId(EVP_PKEY *key) {
    if (!key) return {};
    uint8_t *der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0 || !der) return {};
    Bytes digest(32);
    unsigned int outLen = 0;
    EVP_Digest(der, static_cast<size_t>(len), digest.data(), &outLen, EVP_sha256(), nullptr);
    OPENSSL_free(der);
    return digest;
}
