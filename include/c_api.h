#ifndef C_API_H
#define C_API_H

#include <stddef.h>

#ifdef _WIN32
  #ifdef BUILDING_LAB_CRYPTO_DLL
    #define LAB_API __declspec(dllexport)
  #else
    #define LAB_API __declspec(dllimport)
  #endif
#else
  #define LAB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

LAB_API int lab_api_keygen(const char *alg, const char *out_dir, int force);
LAB_API int lab_api_key_check(const char *priv_path, const char *pub_path);
LAB_API int lab_api_key_info(const char *key_path, char *out_buf, size_t out_len);
LAB_API int lab_api_pub_import(const char *alg, const char *raw_hex, const char *out_path, int force);

LAB_API int lab_api_ec_dbl(const char *curve, const char *point_hex, char *out_hex, size_t out_len);
LAB_API int lab_api_ec_add(const char *curve, const char *p_hex, const char *q_hex, char *out_hex, size_t out_len);
LAB_API int lab_api_ec_mul(const char *curve, const char *p_hex, const char *k_hex, char *out_hex, size_t out_len);
LAB_API int lab_api_ec_validate(const char *curve, const char *point_hex);
LAB_API int lab_api_ec_encode(const char *curve, const char *point_hex, int compress, char *out_hex, size_t out_len);

LAB_API int lab_api_ecdh_selftest(const char *curve, char *out_buf, size_t out_len);
LAB_API int lab_api_x25519_selftest(char *out_buf, size_t out_len);

LAB_API int lab_api_encrypt(const char *recipient_pub, const char *in_file, const char *out_file, int force);
LAB_API int lab_api_decrypt(const char *recipient_priv, const char *in_file, const char *out_file, int force);

LAB_API int lab_api_sign(const char *alg, const char *key_path, const char *in_file, const char *out_file, int force);
LAB_API int lab_api_verify(const char *sig_path, const char *pub_path, const char *in_file);

LAB_API int lab_api_ecdsa_recover(const char *sig1, const char *sig2, const char *in1, const char *in2, const char *out_key, int force);

LAB_API int lab_api_seal(const char *sender_priv, const char *recipient_pub, const char *in_file, const char *out_file, int force);
LAB_API int lab_api_open(const char *recipient_priv, const char *sender_pub, const char *in_file, const char *out_file, int force);

LAB_API int lab_api_run_cmd(const char *cmd_line, char *out_buf, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
