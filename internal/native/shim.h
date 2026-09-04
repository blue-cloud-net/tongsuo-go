#ifndef TONGSUO_GO_SHIM_H
#define TONGSUO_GO_SHIM_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/ocsp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

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

/*
 * X.509 结构化解析与交换。
 * 所有返回 malloc（OPENSSL_malloc）字符串的函数，调用方必须用 X_OPENSSL_free 释放；
 * 栈/扩展等对象统一以 void * 传递，规避 cgo 对 STACK_OF 宏类型的限制。
 */

/* 通用释放 */
void X_OPENSSL_free(void *ptr);

/* X509_NAME 条目枚举 */
int X_X509_NAME_entry_count(const X509_NAME *n);
void *X_X509_NAME_get_entry(const X509_NAME *n, int i);   /* X509_NAME_ENTRY* */
int X_X509_NAME_ENTRY_nid(const void *e);                  /* NID 或 NID_undef */
char *X_X509_NAME_ENTRY_value(const void *e);              /* UTF-8，调用方 free */
char *X_X509_NAME_oneline(const X509_NAME *n);             /* "/CN=.." 文本，调用方 free */

/* 带 X509V3_CTX 的扩展创建（SKID 需要 subject 公钥、AKID 需要 issuer 证书）。 */
int X_X509V3_EXT_conf_nid_ctx(X509 *target, X509 *subject, X509 *issuer,
                              int nid, const char *value);

/* 同上，但 target 为 X509_CRL（CRL 的 AKID 扩展）。 */
int X_X509V3_EXT_conf_nid_ctx_crl(X509_CRL *target, X509 *issuer,
                                   int nid, const char *value);

/* SAN（GENERAL_NAMES 栈） */
void *X_X509_get_san(const X509 *x);                       /* GENERAL_NAMES* 或 NULL */
void X_GENERAL_NAMES_free(void *sk);
int X_GENERAL_NAMES_num(const void *sk);
void *X_GENERAL_NAMES_value(const void *sk, int i);        /* GENERAL_NAME* */
int X_GENERAL_NAME_type(const void *gn);
char *X_GENERAL_NAME_to_string(const void *gn);            /* 值文本，调用方 free */

/* KeyUsage（ASN1_BIT_STRING） */
void *X_X509_get_key_usage(const X509 *x);                 /* ASN1_BIT_STRING* 或 NULL */
void X_ASN1_BIT_STRING_free(void *bs);

/* EKU（EXTENDED_KEY_USAGE 栈） */
void *X_X509_get_eku(const X509 *x);                       /* EXTENDED_KEY_USAGE* 或 NULL */
void X_EXTENDED_KEY_USAGE_free(void *sk);
int X_EXTENDED_KEY_USAGE_num(const void *sk);
void *X_EXTENDED_KEY_USAGE_value(const void *sk, int i);   /* ASN1_OBJECT* */
char *X_OBJ_to_string(const void *o);                      /* 名称或 OID，调用方 free */

/* BasicConstraints */
void *X_X509_get_basic_constraints(const X509 *x);         /* BASIC_CONSTRAINTS* 或 NULL */
void X_BASIC_CONSTRAINTS_free(void *bc);
int X_BASIC_CONSTRAINTS_ca(const void *bc);
long X_BASIC_CONSTRAINTS_pathlen(const void *bc);

/* CSR 扩展栈 */
void *X_sk_X509_EXTENSION_new_null(void);                  /* STACK_OF(X509_EXTENSION)* */
int X_sk_X509_EXTENSION_push(void *sk, void *ext);
void X_sk_X509_EXTENSION_free(void *sk);
void X_sk_X509_EXTENSION_pop_free(void *sk);               /* 连同元素一起释放 */
int X_sk_X509_EXTENSION_num(const void *sk);
void *X_sk_X509_EXTENSION_value(const void *sk, int i);    /* X509_EXTENSION* */
int X_X509_REQ_add_extensions(X509_REQ *r, void *sk);
void *X_X509_REQ_get_extensions(X509_REQ *r);              /* 调用方 pop_free */
int X_X509_REQ_set_challenge_password(X509_REQ *r, const char *pwd);
char *X_X509_REQ_get_challenge_password(X509_REQ *r);      /* 调用方 free */

/*
 * 证书链验证与吊销。
 * X509_STORE_CTX_set0_untrusted 的 STACK_OF(X509) 以 void * 传递。
 */

/* X509 栈（中间证书链 / 已验证链） */
void *X_sk_X509_new_null(void);                             /* STACK_OF(X509)* */
int X_sk_X509_push(void *sk, void *x);
void X_sk_X509_free(void *sk);
void X_sk_X509_pop_free(void *sk);                          /* 连同元素一起释放 */
int X_sk_X509_num(const void *sk);
void *X_sk_X509_value(const void *sk, int i);               /* X509* */

/* 已验证链设置（所有权转移给 ctx，不再单独释放） */
void X_X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, void *sk);

/* CRL 吊销条目栈（内部指针，勿释放） */
int X_sk_X509_REVOKED_num(const void *sk);
void *X_sk_X509_REVOKED_value(const void *sk, int i);       /* X509_REVOKED* */

/* CRL 吊销原因枚举释放 */
void X_ASN1_ENUMERATED_free(void *a);

/* CRL PEM 读写（回调固定 NULL） */
X509_CRL *X_PEM_read_bio_X509_CRL(BIO *bp);
int X_PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x);

/* CRL AuthorityKeyIdentifier keyid 提取（内部指针，不释放）。
 * 返回值所有权归调用者，必须通过 X_OPENSSL_free 释放；无 AKID 或无 keyid 时返回 NULL。 */
unsigned char *X_X509_CRL_get_akid_keyid(X509_CRL *crl, int *out_len);

/*
 * RSA / EC 密钥体系。
 * EVP_PKEY_Q_keygen 为可变参数函数，分别包装 RSA（size_t bits）与 EC（char *curve）。
 * 口令回调经 void* 上下文（u）传递，规避 cgo 对函数指针类型的限制。
 */
EVP_PKEY *X_EVP_PKEY_Q_keygen_rsa(int bits);
EVP_PKEY *X_EVP_PKEY_Q_keygen_ec(const char *curve);
EVP_PKEY *X_PEM_read_bio_PrivateKey_pass(BIO *bp, const char *pass);
int X_PEM_write_bio_PrivateKey_enc(BIO *bp, EVP_PKEY *x, const char *pass);
RSA *X_PEM_read_bio_RSAPrivateKey(BIO *bp);
int X_PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *rsa);

/*
 * PKCS#12 / PKCS#7 容器格式。
 * STACK_OF(X509) 以 void* / 数组形式传递，规避 cgo 类型限制；
 * PKCS7 证书提取经公开结构体 p7->d.sign->cert 访问（铜锁无 PKCS7_get_certificates）。
 */
PKCS12 *X_PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey,
                        X509 *cert, void **ca, int ca_len);
int X_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey,
                   X509 **cert, void **ca);
void *X_PKCS7_get0_certificates(PKCS7 *p7); /* STACK_OF(X509)* 内部指针，勿释放 */

/* OCSP 响应签名验证（STACK_OF(X509) 以 void* 传递）。 */
int X_OCSP_basic_verify(OCSP_BASICRESP *bs, void *certs, X509_STORE *st,
                        unsigned long flags);

/*
 * KDF（EVP_KDF）。
 * HKDF / PBKDF2 的 OSSL_PARAM 数组在 C 侧构造，规避 cgo 对 OSSL_PARAM 结构体
 * 数组的限制；digest 以算法名（如 "SHA256"）传入，由 provider 解析。
 * 返回值遵循 OpenSSL 惯例：成功 1，失败 0（错误入队列，经 ERR_get_error 读取）。
 */
int X_EVP_KDF_HKDF(const char *digest, int mode,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *salt, size_t salt_len,
                   const unsigned char *info, size_t info_len,
                   unsigned char *out, size_t out_len);
int X_EVP_KDF_PBKDF2(const char *digest,
                     const unsigned char *pass, size_t pass_len,
                     const unsigned char *salt, size_t salt_len,
                     int iter,
                     unsigned char *out, size_t out_len);
/* 探测某 KDF 算法是否可用（成功返回 1 并清空 fetch 失败入队的错误）。 */
int X_EVP_KDF_available(const char *algorithm);

#endif /* TONGSUO_GO_SHIM_H */
