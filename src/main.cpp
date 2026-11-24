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

int main(int argc, char **argv) {
    if (argc < 2) {
        cerr << "Usage: lab03 <subcommand> [args...]" << endl;
        cerr << "Subcommands:" << endl;
        cerr << "  ec-add, ec-dbl, ec-mul, ec-validate, ec-encode, ec-invalid-curve-demo" << endl;
        cerr << "  keygen, key-info, key-check, pub-import" << endl;
        cerr << "  ecdh-selftest, x25519-selftest, ecies-encrypt, ecies-decrypt" << endl;
        cerr << "  sign, verify, rsa-sig-demo" << endl;
        cerr << "  ecdsa-demo, ecdsa-recover" << endl;
        cerr << "  ed25519-demo, sig-bench" << endl;
        cerr << "  seal, open" << endl;
        return RET_USAGE;
    }

    string cmd = argv[1];

    if (cmd == "ec-add") return handleEcAdd(argc, argv);
    if (cmd == "ec-dbl") return handleEcDbl(argc, argv);
    if (cmd == "ec-mul") return handleEcMul(argc, argv);
    if (cmd == "ec-validate") return handleEcValidate(argc, argv);
    if (cmd == "ec-encode") return handleEcEncode(argc, argv);
    if (cmd == "ec-invalid-curve-demo") return handleEcInvalidCurveDemo();

    if (cmd == "keygen") return handleKeyGen(argc, argv);
    if (cmd == "key-info") return handleKeyInfo(argc, argv);
    if (cmd == "key-check") return handleKeyCheck(argc, argv);
    if (cmd == "pub-import") return handlePubImport(argc, argv);

    if (cmd == "ecdh-selftest") return handleEcdhSelfTest(argc, argv);
    if (cmd == "x25519-selftest") return handleX25519SelfTest();
    if (cmd == "ecies-encrypt") return handleEciesEncrypt(argc, argv);
    if (cmd == "ecies-decrypt") return handleEciesDecrypt(argc, argv);

    if (cmd == "sign") return handleSign(argc, argv);
    if (cmd == "verify") return handleVerify(argc, argv);
    if (cmd == "rsa-sig-demo") return handleRsaSigDemo();

    if (cmd == "ecdsa-demo") return handleEcdsaDemo(argc, argv);
    if (cmd == "ecdsa-recover") return handleEcdsaRecover(argc, argv);

    if (cmd == "ed25519-demo") return handleEd25519Demo();
    if (cmd == "sig-bench") return handleSigBench(argc, argv);

    if (cmd == "seal") return handleSeal(argc, argv);
    if (cmd == "open") return handleOpen(argc, argv);

    cerr << "Unknown subcommand: " << cmd << endl;
    return RET_USAGE;
}
