#ifndef TONGSUO_GO_SHIM_H
#define TONGSUO_GO_SHIM_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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
 * Phase 8：X.509 结构化解析与交换。
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

#endif /* TONGSUO_GO_SHIM_H */
