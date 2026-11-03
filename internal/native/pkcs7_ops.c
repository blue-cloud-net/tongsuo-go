#include "shim.h"

PKCS7 *X_PKCS7_sign(X509 *cert, EVP_PKEY *key, STACK_OF(X509) *extra,
                   BIO *input, const char *digest, int detached) {
 int flags = PKCS7_BINARY | (detached ? PKCS7_DETACHED : 0);
 const EVP_MD *md = EVP_get_digestbyname(digest);
 PKCS7 *p7;
 if (md == NULL) return NULL;
 p7 = PKCS7_sign(NULL, NULL, extra, NULL, flags | PKCS7_PARTIAL);
 if (p7 == NULL) return NULL;
 if (PKCS7_sign_add_signer(p7, cert, key, md, PKCS7_NOSMIMECAP) == NULL
     || !PKCS7_final(p7, input, flags)) { PKCS7_free(p7); return NULL; }
 return p7;
}
int X_PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *extra, BIO *input, int supplied, BIO *out) {
 if (!PKCS7_type_is_signed(p7) || sk_PKCS7_SIGNER_INFO_num(PKCS7_get_signer_info(p7)) <= 0) return 0;
 if (!!PKCS7_get_detached(p7) != !!supplied) return 0;
 return PKCS7_verify(p7, extra, NULL, supplied ? input : NULL, out, PKCS7_BINARY | PKCS7_NOVERIFY);
}
PKCS7 *X_PKCS7_encrypt(STACK_OF(X509) *recipients, BIO *input, const char *name) {
 const EVP_CIPHER *cipher = EVP_get_cipherbyname(name);
 return cipher == NULL ? NULL : PKCS7_encrypt(recipients, input, cipher, PKCS7_BINARY);
}
int X_PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *key, X509 *cert, BIO *out) {
 return PKCS7_type_is_enveloped(p7) && PKCS7_decrypt(p7, key, cert, out, PKCS7_BINARY);
}
