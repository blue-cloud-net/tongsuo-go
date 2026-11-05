#include "algorithms.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

/* Return -2 when the provider cannot apply the requested parameters. */
int X_EVP_DigestSignVerifyInit_instance(EVP_MD_CTX *ctx, EVP_PKEY *key,
    const char *instance, const unsigned char *context, size_t context_len, int sign)
{
    if (context_len == 0 && (OPENSSL_strcasecmp(instance, "Ed25519") == 0
        || OPENSSL_strcasecmp(instance, "Ed448") == 0)) {
        return sign ? EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL)
                    : EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL);
    }
#if defined(OSSL_SIGNATURE_PARAM_INSTANCE) && defined(OSSL_SIGNATURE_PARAM_CONTEXT_STRING)
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char empty = 0;
    const OSSL_PARAM *settable;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, (char *)instance, strlen(instance) + 1),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            context_len ? (void *)context : &empty, context_len),
        OSSL_PARAM_END
    };
    int ok = sign ? EVP_DigestSignInit_ex(ctx, &pctx, NULL, NULL, NULL, key, params)
                  : EVP_DigestVerifyInit_ex(ctx, &pctx, NULL, NULL, NULL, key, params);
    if (ok != 1)
        return 0;
    /* Reject providers that ignore unknown OSSL_PARAM keys. Some providers
     * advertise context/instance as retrievable but do not actually return them. */
    settable = EVP_PKEY_CTX_settable_params(pctx);
    if (settable == NULL
        || OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_INSTANCE) == NULL
        || OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_CONTEXT_STRING) == NULL)
        return -2;
    return 1;
#else
    return -2;
#endif
}

int X_EVP_PKEY_SM2DH(EVP_PKEY *ephemeral, EVP_PKEY *peer_ephemeral,
    EVP_PKEY *self_static, EVP_PKEY *peer_static, int initiator,
    const unsigned char *self_id, size_t self_id_len,
    const unsigned char *peer_id, size_t peer_id_len,
    unsigned char *out, size_t outlen)
{
#if defined(OSSL_EXCHANGE_PARAM_SELF_ENC_KEY) && defined(OSSL_EXCHANGE_PARAM_PEER_ENC_KEY)
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char empty = 0;
    size_t n = outlen;
    int ok = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_INITIATOR, &initiator),
        OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_SELF_ENC_KEY, (void **)&self_static, sizeof(self_static)),
        OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_PEER_ENC_KEY, (void **)&peer_static, sizeof(peer_static)),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_SELF_ID,
            self_id_len ? (void *)self_id : &empty, self_id_len),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_PEER_ID,
            peer_id_len ? (void *)peer_id : &empty, peer_id_len),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_DIGEST, "SM3", sizeof("SM3")),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_OUTLEN, &outlen),
        OSSL_PARAM_END
    };
    EVP_KEYEXCH *exchange = EVP_KEYEXCH_fetch(NULL, "SM2DH", NULL);
    if (exchange == NULL) return -2;
    EVP_KEYEXCH_free(exchange);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ephemeral, NULL);
    if (ctx != NULL && EVP_PKEY_derive_init_ex(ctx, params) == 1
        && EVP_PKEY_derive_set_peer(ctx, peer_ephemeral) == 1
        && EVP_PKEY_derive(ctx, out, &n) == 1 && n == outlen)
        ok = 1;
    EVP_PKEY_CTX_free(ctx);
    return ok;
#else
    return -2;
#endif
}
