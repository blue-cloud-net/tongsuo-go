#ifndef TONGSUO_GO_SHIM_H
#define TONGSUO_GO_SHIM_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/*
 * X_EVP_Digest：一次性摘要。EVP_Digest 在部分 OpenSSL 版本中为可变参数宏，
 * 铜锁 8.x 中为普通函数。统一经 C 包装以规避跨版本差异，供 Go 侧调用。
 */
int X_EVP_Digest(const EVP_MD *md, const unsigned char *data, size_t count,
                 unsigned char *md_out, unsigned int *size);

/*
 * X_EVP_PKEY_Q_keygen_sm2：生成 SM2 密钥对。
 * EVP_PKEY_Q_keygen 为可变参数函数，经 C 包装以规避 cgo 限制。
 */
EVP_PKEY *X_EVP_PKEY_Q_keygen_sm2(void);

/*
 * PEM 读写（EVP_PKEY 层）。回调/口令等参数固定为 NULL，
 * 避免 cgo 对 pem_password_cb 函数指针类型的桥接问题。
 */
EVP_PKEY *X_PEM_read_bio_PrivateKey(BIO *bp);
int X_PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x);
EVP_PKEY *X_PEM_read_bio_PUBKEY(BIO *bp);
int X_PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);

/* X.509 证书 / CSR 的 PEM 读写（固定回调参数为 NULL）。 */
X509 *X_PEM_read_bio_X509(BIO *bp);
int X_PEM_write_bio_X509(BIO *bp, X509 *x);
X509_REQ *X_PEM_read_bio_X509_REQ(BIO *bp);
int X_PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x);

#endif /* TONGSUO_GO_SHIM_H */
