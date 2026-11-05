/* Test-only independent EVP driver. Arguments: cipher key nonce aad tag enc|dec.
 * Input/output are binary; encryption appends an AEAD tag when applicable.
 * No SDK shims or algorithm implementations are used here. */
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *unhex(const char *s, long *n) {
    if (*s == 0) { *n = 0; return OPENSSL_zalloc(1); }
    return OPENSSL_hexstr2buf(s, n);
}
int main(int argc, char **argv) {
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *key = NULL, *iv = NULL, *aad = NULL, *tag = NULL;
    unsigned char input[1048576], *out = NULL, empty = 0;
    long kn, in, an, tn;
    size_t n;
    int enc, aead, len = 0, total = 0, ret = 1;
    if (argc != 7) return 2;
    enc = strcmp(argv[6], "enc") == 0;
    cipher = EVP_CIPHER_fetch(NULL, argv[1], NULL);
    ctx = EVP_CIPHER_CTX_new();
    key = unhex(argv[2], &kn); iv = unhex(argv[3], &in);
    aad = unhex(argv[4], &an); tag = unhex(argv[5], &tn);
    if (!cipher || !ctx || !key || !iv || !aad || !tag) goto done;
    if (kn != EVP_CIPHER_get_key_length(cipher)) goto done;
    aead = (EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;
    n = fread(input, 1, sizeof(input), stdin);
    if (ferror(stdin) || !feof(stdin)) goto done;
    out = OPENSSL_malloc(n + 64);
    if (!out) goto done;
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) != 1) goto done;
    if (aead && !enc && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tn, tag) != 1) goto done;
    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, in ? iv : NULL, enc) != 1) goto done;
    if (an && EVP_CipherUpdate(ctx, NULL, &len, aad, (int)an) != 1) goto done;
    if (EVP_CipherUpdate(ctx, out, &len, n ? input : &empty, (int)n) != 1) goto done;
    total = len;
    if (EVP_CipherFinal_ex(ctx, out + total, &len) != 1) goto done;
    total += len;
    if (aead && enc) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + total) != 1) goto done;
        total += 16;
    }
    if (fwrite(out, 1, total, stdout) != (size_t)total) goto done;
    ret = 0;
done:
    if (ret) ERR_print_errors_fp(stderr);
    OPENSSL_free(out); OPENSSL_clear_free(key, key ? kn : 0);
    OPENSSL_free(iv); OPENSSL_free(aad); OPENSSL_free(tag);
    EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(cipher);
    return ret;
}
