#ifndef TONGSUO_GO_ALGORITHMS_H
#define TONGSUO_GO_ALGORITHMS_H
#include <openssl/evp.h>
int X_EVP_DigestSignVerifyInit_instance(EVP_MD_CTX *ctx, EVP_PKEY *key,
    const char *instance, const unsigned char *context, size_t context_len, int sign);
int X_EVP_PKEY_SM2DH(EVP_PKEY *ephemeral, EVP_PKEY *peer_ephemeral,
    EVP_PKEY *self_static, EVP_PKEY *peer_static, int initiator,
    const unsigned char *self_id, size_t self_id_len,
    const unsigned char *peer_id, size_t peer_id_len,
    unsigned char *out, size_t outlen);
#endif
