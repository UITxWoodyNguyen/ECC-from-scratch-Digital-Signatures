#include "c_api.h"
#include "common.h"
#include "ec_math.h"
#include "ec_keys.h"
#include "x25519_edu.h"
#include "ecies.h"
#include "sigfile.h"
#include "rsa_sig.h"
#include "ecdsa.h"
#include "eddsa.h"
#include "seal_open.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

// Stream capture helper to capture stdout and stderr
struct StreamCapture {
    ostringstream oss;
    streambuf *oldCout;
    streambuf *oldCerr;

    StreamCapture() {
        oldCout = cout.rdbuf(oss.rdbuf());
        oldCerr = cerr.rdbuf(oss.rdbuf());
    }

    ~StreamCapture() {
        cout.rdbuf(oldCout);
        cerr.rdbuf(oldCerr);
    }

    string str() const {
        return oss.str();
    }
};

// Dispatch arguments to the appropriate module handler
static int runWithArgs(const vector<string> &args, char *out_buf = nullptr, size_t out_len = 0) {
    vector<char *> c_argv;
    for (const auto &s : args) {
        c_argv.push_back(const_cast<char *>(s.c_str()));
    }
    int argc = (int)c_argv.size();
    if (argc < 2) return 1;

    string cmd = c_argv[1];
    StreamCapture cap;
    int ret = 1;

    if (cmd == "keygen") ret = handleKeyGen(argc, c_argv.data());
    else if (cmd == "key-info") ret = handleKeyInfo(argc, c_argv.data());
    else if (cmd == "key-check") ret = handleKeyCheck(argc, c_argv.data());
    else if (cmd == "pub-import") ret = handlePubImport(argc, c_argv.data());
    else if (cmd == "ec-add") ret = handleEcAdd(argc, c_argv.data());
    else if (cmd == "ec-dbl") ret = handleEcDbl(argc, c_argv.data());
    else if (cmd == "ec-mul") ret = handleEcMul(argc, c_argv.data());
    else if (cmd == "ec-validate") ret = handleEcValidate(argc, c_argv.data());
    else if (cmd == "ec-encode") ret = handleEcEncode(argc, c_argv.data());
    else if (cmd == "ec-invalid-curve-demo") ret = handleEcInvalidCurveDemo();
    else if (cmd == "ecdh-selftest") ret = handleEcdhSelfTest(argc, c_argv.data());
    else if (cmd == "x25519-selftest") ret = handleX25519SelfTest();
    else if (cmd == "encrypt" || cmd == "ecies-encrypt") ret = handleEciesEncrypt(argc, c_argv.data());
    else if (cmd == "decrypt" || cmd == "ecies-decrypt") ret = handleEciesDecrypt(argc, c_argv.data());
    else if (cmd == "sign") ret = handleSign(argc, c_argv.data());
    else if (cmd == "verify") ret = handleVerify(argc, c_argv.data());
    else if (cmd == "rsa-sig-demo") ret = handleRsaSigDemo();
    else if (cmd == "ecdsa-demo") ret = handleEcdsaDemo(argc, c_argv.data());
    else if (cmd == "ecdsa-recover") ret = handleEcdsaRecover(argc, c_argv.data());
    else if (cmd == "ed25519-demo") ret = handleEd25519Demo();
    else if (cmd == "sig-bench") ret = handleSigBench(argc, c_argv.data());
    else if (cmd == "seal") ret = handleSeal(argc, c_argv.data());
    else if (cmd == "open") ret = handleOpen(argc, c_argv.data());

    if (out_buf && out_len > 0) {
        string s = cap.str();
        while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) {
            s.pop_back();
        }
        strncpy(out_buf, s.c_str(), out_len - 1);
        out_buf[out_len - 1] = '\0';
    }
    return ret;
}

// Generate key pair
int lab_api_keygen(const char *alg, const char *out_dir, int force) {
    if (!alg || !out_dir) return 1;
    vector<string> args = {"lab03", "keygen", "--alg", alg, "--out-dir", out_dir};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Check key pair
int lab_api_key_check(const char *priv_path, const char *pub_path) {
    if (!priv_path || !pub_path) return 1;
    vector<string> args = {"lab03", "key-check", "--priv", priv_path, "--pub", pub_path};
    return runWithArgs(args);
}

// Key information
int lab_api_key_info(const char *key_path, char *out_buf, size_t out_len) {
    if (!key_path || !out_buf || out_len == 0) return 1;
    vector<string> args = {"lab03", "key-info", "--in", key_path};
    return runWithArgs(args, out_buf, out_len);
}

// Import raw public key
int lab_api_pub_import(const char *alg, const char *raw_hex, const char *out_path, int force) {
    if (!alg || !raw_hex || !out_path) return 1;
    vector<string> args = {"lab03", "pub-import", "--alg", alg, "--raw", raw_hex, "--out", out_path};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Point doubling
int lab_api_ec_dbl(const char *curve, const char *point_hex, char *out_hex, size_t out_len) {
    if (!curve || !point_hex || !out_hex || out_len == 0) return 1;
    vector<string> args = {"lab03", "ec-dbl", "--curve", curve, "-P", point_hex};
    return runWithArgs(args, out_hex, out_len);
}

// Point addition
int lab_api_ec_add(const char *curve, const char *p_hex, const char *q_hex, char *out_hex, size_t out_len) {
    if (!curve || !p_hex || !q_hex || !out_hex || out_len == 0) return 1;
    vector<string> args = {"lab03", "ec-add", "--curve", curve, "-P", p_hex, "-Q", q_hex};
    return runWithArgs(args, out_hex, out_len);
}

// Point scalar multiplication
int lab_api_ec_mul(const char *curve, const char *p_hex, const char *k_hex, char *out_hex, size_t out_len) {
    if (!curve || !k_hex || !out_hex || out_len == 0) return 1;
    vector<string> args = {"lab03", "ec-mul", "--curve", curve};
    if (p_hex && strlen(p_hex) > 0) {
        args.push_back("-P");
        args.push_back(p_hex);
    }
    args.push_back("-k");
    args.push_back(k_hex);
    return runWithArgs(args, out_hex, out_len);
}

// Point validation
int lab_api_ec_validate(const char *curve, const char *point_hex) {
    if (!curve || !point_hex) return 1;
    vector<string> args = {"lab03", "ec-validate", "--curve", curve, "-P", point_hex};
    return runWithArgs(args);
}

// Point encoding conversion
int lab_api_ec_encode(const char *curve, const char *point_hex, int compress, char *out_hex, size_t out_len) {
    if (!curve || !point_hex || !out_hex || out_len == 0) return 1;
    vector<string> args = {"lab03", "ec-encode", "--curve", curve, "-P", point_hex};
    if (compress) args.push_back("--compress");
    else args.push_back("--uncompress");
    return runWithArgs(args, out_hex, out_len);
}

// Self-test for ECDH
int lab_api_ecdh_selftest(const char *curve, char *out_buf, size_t out_len) {
    if (!curve) return 1;
    vector<string> args = {"lab03", "ecdh-selftest", "--curve", curve};
    return runWithArgs(args, out_buf, out_len);
}

// Self-test for X25519
int lab_api_x25519_selftest(char *out_buf, size_t out_len) {
    vector<string> args = {"lab03", "x25519-selftest"};
    return runWithArgs(args, out_buf, out_len);
}

// ECIES encryption
int lab_api_encrypt(const char *recipient_pub, const char *in_file, const char *out_file, int force) {
    if (!recipient_pub || !in_file || !out_file) return 1;
    vector<string> args = {"lab03", "ecies-encrypt", "--recipient-pub", recipient_pub, "--in", in_file, "--out", out_file};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// ECIES decryption
int lab_api_decrypt(const char *recipient_priv, const char *in_file, const char *out_file, int force) {
    if (!recipient_priv || !in_file || !out_file) return 1;
    vector<string> args = {"lab03", "ecies-decrypt", "--recipient-priv", recipient_priv, "--in", in_file, "--out", out_file};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Digital signature
int lab_api_sign(const char *alg, const char *key_path, const char *in_file, const char *out_file, int force) {
    if (!alg || !key_path || !in_file || !out_file) return 1;
    vector<string> args = {"lab03", "sign", "--alg", alg, "--key", key_path, "--in", in_file, "--out", out_file};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Signature verification
int lab_api_verify(const char *sig_path, const char *pub_path, const char *in_file) {
    if (!sig_path || !pub_path || !in_file) return 1;
    vector<string> args = {"lab03", "verify", "--sig", sig_path, "--pub", pub_path, "--in", in_file};
    return runWithArgs(args);
}

// Recover ECDSA private key from reused nonce
int lab_api_ecdsa_recover(const char *sig1, const char *sig2, const char *in1, const char *in2, const char *out_key, int force) {
    if (!sig1 || !sig2 || !in1 || !in2 || !out_key) return 1;
    vector<string> args = {"lab03", "ecdsa-recover", "--sig1", sig1, "--sig2", sig2, "--in1", in1, "--in2", in2, "--out", out_key};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Seal container
int lab_api_seal(const char *sender_priv, const char *recipient_pub, const char *in_file, const char *out_file, int force) {
    if (!sender_priv || !recipient_pub || !in_file || !out_file) return 1;
    vector<string> args = {"lab03", "seal", "--sender-priv", sender_priv, "--recipient-pub", recipient_pub, "--in", in_file, "--out", out_file};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Open container
int lab_api_open(const char *recipient_priv, const char *sender_pub, const char *in_file, const char *out_file, int force) {
    if (!recipient_priv || !sender_pub || !in_file || !out_file) return 1;
    vector<string> args = {"lab03", "open", "--recipient-priv", recipient_priv, "--sender-pub", sender_pub, "--in", in_file, "--out", out_file};
    if (force) args.push_back("--force");
    return runWithArgs(args);
}

// Parse string command line and run
int lab_api_run_cmd(const char *cmd_line, char *out_buf, size_t out_len) {
    if (!cmd_line) return 1;
    istringstream iss(cmd_line);
    vector<string> tokens;
    tokens.push_back("lab03");
    string tok;
    while (iss >> tok) {
        tokens.push_back(tok);
    }
    return runWithArgs(tokens, out_buf, out_len);
}
