#include "shim.h"

#include <string.h>

#include <openssl/bio.h>
#include <openssl/params.h>
#include <openssl/provider.h>

int X_EVP_Digest(const EVP_MD *md, const unsigned char *data, size_t count,
                 unsigned char *md_out, unsigned int *size)
{
    return EVP_Digest(data, count, md_out, size, md, NULL);
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_sm2(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_ed25519(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_ed448(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "ED448");
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_x25519(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_x448(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "X448");
}

/*
 * x_no_pass_cb：不提供口令的 PEM 回调。
 * 传 NULL 回调会让 OpenSSL 退回默认 UI 回调并向终端（/dev/tty）索要口令，
 * 对库调用而言会阻塞在没有终端的进程里。这里显式返回 0，让加密 PEM 解析
 * 直接失败并把错误交给调用方（调用方应改用带口令的入口）。
 *
 * x_no_pass_cb is a PEM callback that never supplies a pass phrase.
 * Passing a NULL callback makes OpenSSL fall back to the default UI
 * callback, which asks the terminal (/dev/tty) for a pass phrase and
 * blocks in processes without one. Returning 0 makes encrypted PEM
 * parsing fail cleanly so the caller can use the pass phrase aware
 * entry instead.
 */
static int x_no_pass_cb(char *buf, int size, int rwflag, void *u)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    return 0;
}

EVP_PKEY *X_PEM_read_bio_PrivateKey(BIO *bp)
{
    return PEM_read_bio_PrivateKey(bp, NULL, x_no_pass_cb, NULL);
}

int X_PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x)
{
    return PEM_write_bio_PrivateKey(bp, x, NULL, NULL, 0, NULL, NULL);
}

EVP_PKEY *X_PEM_read_bio_PUBKEY(BIO *bp)
{
    return PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x)
{
    return PEM_write_bio_PUBKEY(bp, x);
}

void X_OPENSSL_cleanse(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0)
        return;
    OPENSSL_cleanse(ptr, len);
}

X509 *X_PEM_read_bio_X509(BIO *bp)
{
    return PEM_read_bio_X509(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_X509(BIO *bp, X509 *x)
{
    return PEM_write_bio_X509(bp, x);
}

X509_REQ *X_PEM_read_bio_X509_REQ(BIO *bp)
{
    return PEM_read_bio_X509_REQ(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x)
{
    return PEM_write_bio_X509_REQ(bp, x);
}

void X_OPENSSL_free(void *ptr)
{
    OPENSSL_free(ptr);
}

/*
 * X_SSL_CTX_set_verify 包装 SSL_CTX_set_verify，固定 callback 为 NULL。
 *
 * cgo 不允许 Go 端把 untyped nil 当作 SSL_verify_cb 函数指针传入 C 函
 * 数（callback 参数为函数指针，类型系统不接受 nil 字面量），所以必须
 * 由 C shim 把 NULL 显式传入。
 */
void X_SSL_CTX_set_verify(SSL_CTX *ctx, int mode)
{
    SSL_CTX_set_verify(ctx, mode, NULL);
}

char *X_X509_verify_cert_error_string(long err)
{
    /* X509_verify_cert_error_string 在不同 OpenSSL 版本签名不同；为
     * 兼容 Tongsuo 8.5 与 OpenSSL 3.x，均返回 const char*，统一返回
     * 字符串副本（OPENSSL_strdup 由 OPENSSL_free 释放）。 */
    const char *msg = X509_verify_cert_error_string(err);
    if (msg == NULL)
        return NULL;
    return OPENSSL_strdup(msg);
}

void X_SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
    SSL_CTX_set_verify_depth(ctx, depth);
}

int X_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    return SSL_CTX_set_default_verify_paths(ctx);
}

/*
 * X_SSL_set_tlsext_host_name 包装 SSL_set_tlsext_host_name 宏。
 *
 * SSL_set_tlsext_host_name 是宏（SSL_ctrl 的封装），cgo 无法直接调用宏，
 * 故由 C shim 提供函数入口。
 *
 * 作用：在 ClientHello 中填入 server_name 扩展（SNI）。这是**路由**扩展，
 * 与证书校验（SSL_set1_host / X509_VERIFY_PARAM）完全独立：
 *   - 缺失 SNI 时，绝大多数真实站点（CDN / 虚拟主机 / 多证书部署）会直接
 *     回 `sslv3 alert handshake failure`（alert 40），握手根本走不到验证阶段；
 *   - 因此即使客户端配置为 VERIFY_NONE（不校验证书），也必须发送 SNI。
 *
 * 返回值遵循 OpenSSL 惯例：成功 1，失败 0（错误入队列，经 ERR_get_error 读取）。
 */
int X_SSL_set_tlsext_host_name(SSL *ssl, const char *name)
{
    return SSL_set_tlsext_host_name(ssl, name) == 1;
}

int X_X509_NAME_entry_count(const X509_NAME *n)
{
    return X509_NAME_entry_count(n);
}

void *X_X509_NAME_get_entry(const X509_NAME *n, int i)
{
    return X509_NAME_get_entry(n, i);
}

int X_X509_NAME_ENTRY_nid(const void *e)
{
    const X509_NAME_ENTRY *entry = (const X509_NAME_ENTRY *)e;
    ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(entry);
    if (o == NULL)
        return NID_undef;
    return OBJ_obj2nid(o);
}

char *X_X509_NAME_ENTRY_value(const void *e)
{
    const X509_NAME_ENTRY *entry = (const X509_NAME_ENTRY *)e;
    ASN1_STRING *s = X509_NAME_ENTRY_get_data(entry);
    if (s == NULL)
        return NULL;
    unsigned char *out = NULL;
    int n = ASN1_STRING_to_UTF8(&out, s);
    if (n < 0)
        return NULL;
    return (char *)out;
}

char *X_X509_NAME_oneline(const X509_NAME *n)
{
    char buf[4096];
    if (X509_NAME_oneline(n, buf, sizeof(buf)) == NULL)
        return NULL;
    return OPENSSL_strdup(buf);
}

/*
 * x_ext_build 按 OpenSSL 扩展配置语法构造一个 X509_EXTENSION。
 *
 * 两件事必须同时做到，缺一扩展就会失败或崩溃：
 *   1. 注入配置库（X509V3_set_nconf）。OpenSSL 的 do_ext_nconf 在处理
 *      r2i 类扩展（certificatePolicies / proxyCertInfo 等）时要求
 *      ctx->db 与 ctx->db_meth 均非空，否则抛 X509V3_R_NO_CONFIG_DATABASE。
 *      这里用空 CONF 满足该要求：内联 OID 形式的 value 不需要任何配置段。
 *   2. 传入正确的上下文对象。ctx->subject_cert / subject_req / issuer_cert
 *      会被扩展解析器直接解引用——例如 subjectAltName 的 "email:copy" 要读
 *      subject 的 emailAddress、authorityKeyIdentifier 要读 issuer 的 SKID。
 *      ctx 为 NULL 时这些路径会直接段错误。
 *
 * subject / issuer / req 均可为 NULL（表示该维度无上下文）。
 * 返回的扩展由调用方负责 X509_EXTENSION_free。
 */
static X509_EXTENSION *x_ext_build(X509 *subject, X509 *issuer, X509_REQ *req,
                                    int nid, const char *value)
{
    if (value == NULL)
        return NULL;

    CONF *conf = NCONF_new(NULL);
    if (conf == NULL)
        return NULL;

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, subject, req, NULL, 0);
    /* 必须放在 X509V3_set_ctx 之后：set_ctx 会把 ctx->db 置空。 */
    X509V3_set_nconf(&ctx, conf);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

    NCONF_free(conf);
    return ext;
}

int X_X509V3_EXT_conf_nid_ctx(X509 *target, X509 *subject, X509 *issuer,
                              int nid, const char *value)
{
    X509_EXTENSION *ext = x_ext_build(subject, issuer, NULL, nid, value);
    if (ext == NULL)
        return 0;
    int ok = X509_add_ext(target, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
}

X509_EXTENSION *X_X509V3_EXT_conf_nid_ctx_new(X509 *subject, X509 *issuer,
                                               X509_REQ *req, int nid,
                                               const char *value)
{
    return x_ext_build(subject, issuer, req, nid, value);
}

int X_X509V3_EXT_conf_nid_ctx_crl(X509_CRL *target, X509 *issuer,
                                   int nid, const char *value)
{
    X509_EXTENSION *ext = x_ext_build(NULL, issuer, NULL, nid, value);
    if (ext == NULL)
        return 0;
    int ok = X509_CRL_add_ext(target, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
}

/*
 * 读取 ASN.1 对象的 tag、长度头字节数与内容长度（DER）。
 * 返回内容字节数；失败返回 -1。
 */
static int der_seq_content(const unsigned char *der, int len,
                           unsigned char *tag_out, int *hdr_out,
                           int *content_out)
{
    if (der == NULL || len < 2)
        return -1;
    int idx = 0;
    tag_out[0] = der[idx++];
    unsigned char l = der[idx++];
    int content;
    if ((l & 0x80) == 0) {
        content = l;
    } else {
        int nbytes = l & 0x7F;
        if (nbytes < 1 || nbytes > 4 || idx + nbytes > len)
            return -1;
        content = 0;
        for (int i = 0; i < nbytes; i++)
            content = (content << 8) | der[idx + i];
        idx += nbytes;
    }
    if (content < 0 || idx + content > len)
        return -1;
    *hdr_out = idx;
    *content_out = content;
    return content;
}

/* 按 DER 长度规则写长度字节，返回写入的字节数。 */
static int der_write_len(unsigned char *buf, int content)
{
    if (content < 0x80) {
        buf[0] = (unsigned char)content;
        return 1;
    }
    unsigned char tmp[4];
    int n = 0;
    unsigned int v = (unsigned int)content;
    while (v > 0) {
        tmp[n++] = (unsigned char)(v & 0xFF);
        v >>= 8;
    }
    buf[0] = (unsigned char)(0x80 | n);
    for (int i = 0; i < n; i++)
        buf[1 + i] = tmp[n - 1 - i];
    return 1 + n;
}

int X_X509V3_EXT_conf_nid_merge(X509 *x, int nid, const char *value)
{
    if (x == NULL || value == NULL)
        return 0;

    /* 1. 定位已有的同 NID 扩展 */
    int loc = -1;
    int n = X509_get_ext_count(x);
    for (int i = 0; i < n; i++) {
        X509_EXTENSION *e = X509_get_ext(x, i);
        if (e != NULL &&
            OBJ_obj2nid(X509_EXTENSION_get_object(e)) == nid) {
            loc = i;
            break;
        }
    }
    if (loc < 0)
        return 0; /* 无既有扩展：调用方走普通追加 */

    X509_EXTENSION *old = X509_get_ext(x, loc);
    int crit = X509_EXTENSION_get_critical(old);

    /* 2. 解析出两侧的 SEQUENCE 内容 */
    ASN1_OCTET_STRING *os_old = X509_EXTENSION_get_data(old);
    const unsigned char *d_old = ASN1_STRING_get0_data(os_old);
    int l_old = ASN1_STRING_length(os_old);

    unsigned char tag_old = 0, tag_new = 0;
    int hdr_old = 0, con_old = 0, hdr_new = 0, con_new = 0;
    if (der_seq_content(d_old, l_old, &tag_old, &hdr_old, &con_old) < 0)
        return 0;

    /* 用 x 本身作为 subject 上下文：可重复 OID 的合并值可能引用
     * subject 的 emailAddress 等信息（subjectAltName 的 "email:copy"）。 */
    X509_EXTENSION *tmp = x_ext_build(x, NULL, NULL, nid, value);
    if (tmp == NULL)
        return 0;
    ASN1_OCTET_STRING *os_new = X509_EXTENSION_get_data(tmp);
    const unsigned char *d_new = ASN1_STRING_get0_data(os_new);
    int l_new = ASN1_STRING_length(os_new);
    int parsed = der_seq_content(d_new, l_new, &tag_new, &hdr_new, &con_new);
    if (parsed < 0) {
        X509_EXTENSION_free(tmp);
        return 0;
    }
    /* 只在两侧都是同 tag 的 SEQUENCE 时合并；否则退回普通追加。 */
    if (tag_old != tag_new || tag_old != 0x30) {
        X509_EXTENSION_free(tmp);
        return 0;
    }

    /* 3. 拼接内容并重新封装成 DER */
    int total = con_old + con_new;
    unsigned char *merged = OPENSSL_malloc((size_t)hdr_old + total + 8);
    if (merged == NULL) {
        X509_EXTENSION_free(tmp);
        return 0;
    }
    int p = 0;
    merged[p++] = 0x30;
    p += der_write_len(merged + p, total);
    memcpy(merged + p, d_old + hdr_old, (size_t)con_old);
    p += con_old;
    memcpy(merged + p, d_new + hdr_new, (size_t)con_new);
    p += con_new;
    X509_EXTENSION_free(tmp);

    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    if (os == NULL) {
        OPENSSL_free(merged);
        return 0;
    }
    if (!ASN1_OCTET_STRING_set(os, merged, p)) {
        OPENSSL_free(merged);
        ASN1_OCTET_STRING_free(os);
        return 0;
    }
    OPENSSL_free(merged);

    X509_EXTENSION *newext =
        X509_EXTENSION_create_by_OBJ(NULL, OBJ_nid2obj(nid), crit, os);
    ASN1_OCTET_STRING_free(os);
    if (newext == NULL)
        return 0;

    /* 4. 原位替换 */
    X509_EXTENSION *rm = X509_delete_ext(x, loc);
    if (rm != NULL)
        X509_EXTENSION_free(rm);
    int ok = X509_add_ext(x, newext, loc);
    X509_EXTENSION_free(newext);
    return ok == 1 ? 1 : 0;
}

/*
 * X_X509_EXTENSION_create_by_NID_der：按 NID 与已编码的 DER 值构造扩展。
 *
 * X509_EXTENSION_create_by_NID 要求扩展值以 ASN1_OCTET_STRING 形式给出；
 * 这里把调用方提供的 der 原样装进去，因此 der 就是扩展值的完整 DER
 * （不含外层 OCTET STRING 的 tag / length）。OpenSSL 不校验扩展值内容，
 * 合法性由调用方保证。
 */
X509_EXTENSION *X_X509_EXTENSION_create_by_NID_der(int nid, int crit,
                                                   const unsigned char *der,
                                                   int len)
{
    if (der == NULL || len < 0)
        return NULL;

    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return NULL;
    if (!ASN1_OCTET_STRING_set(os, der, len)) {
        ASN1_OCTET_STRING_free(os);
        return NULL;
    }
    /* create_by_NID 内部会复制 os，故此处可立即释放。 */
    X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(NULL, nid, crit, os);
    ASN1_OCTET_STRING_free(os);
    return ext;
}

void *X_X509_get_san(const X509 *x)
{
    return X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
}

void X_GENERAL_NAMES_free(void *sk)
{
    GENERAL_NAMES_free((GENERAL_NAMES *)sk);
}

int X_GENERAL_NAMES_num(const void *sk)
{
    return sk_GENERAL_NAME_num((const GENERAL_NAMES *)sk);
}

void *X_GENERAL_NAMES_value(const void *sk, int i)
{
    return sk_GENERAL_NAME_value((const GENERAL_NAMES *)sk, i);
}

int X_GENERAL_NAME_type(const void *gn)
{
    const GENERAL_NAME *g = (const GENERAL_NAME *)gn;
    if (g == NULL)
        return -1;
    return g->type;
}

char *X_GENERAL_NAME_to_string(const void *gn)
{
    const GENERAL_NAME *g = (const GENERAL_NAME *)gn;
    if (g == NULL)
        return NULL;
    int ptype = 0;
    const void *val = GENERAL_NAME_get0_value(g, &ptype);
    if (val == NULL)
        return NULL;
    switch (ptype) {
    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI: {
        const ASN1_IA5STRING *s = (const ASN1_IA5STRING *)val;
        unsigned char *out = NULL;
        int n = ASN1_STRING_to_UTF8(&out, s);
        if (n < 0)
            return NULL;
        return (char *)out;
    }
    case GEN_IPADD: {
        const ASN1_OCTET_STRING *ip = (const ASN1_OCTET_STRING *)val;
        const unsigned char *d = ASN1_STRING_get0_data(ip);
        int n = ASN1_STRING_length(ip);
        char buf[128];
        if (d != NULL && n == 4) {
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", d[0], d[1], d[2], d[3]);
        } else if (d != NULL && n == 16) {
            char tmp[32];
            buf[0] = '\0';
            for (int i = 0; i < 8; i++) {
                snprintf(tmp, sizeof(tmp), "%s%x", i ? ":" : "",
                         (unsigned)((d[2 * i] << 8) | d[2 * i + 1]));
                strncat(buf, tmp, sizeof(buf) - strlen(buf) - 1);
            }
        } else {
            snprintf(buf, sizeof(buf), "IP:%d bytes", n);
        }
        return OPENSSL_strdup(buf);
    }
    case GEN_RID: {
        const ASN1_OBJECT *o = (const ASN1_OBJECT *)val;
        char buf[256];
        OBJ_obj2txt(buf, sizeof(buf), o, 1);
        return OPENSSL_strdup(buf);
    }
    case GEN_OTHERNAME: {
        ASN1_OBJECT *oid = NULL;
        ASN1_TYPE *oval = NULL;
        if (GENERAL_NAME_get0_otherName(g, &oid, &oval) <= 0 || oid == NULL)
            return NULL;
        char buf[256];
        OBJ_obj2txt(buf, sizeof(buf), oid, 1);
        size_t blen = strlen(buf);
        char *r = OPENSSL_malloc(blen + 16);
        if (r == NULL)
            return NULL;
        snprintf(r, blen + 16, "otherName:%s", buf);
        return r;
    }
    case GEN_DIRNAME: {
        const X509_NAME *nm = (const X509_NAME *)val;
        return X_X509_NAME_oneline(nm);
    }
    default:
        return OPENSSL_strdup("unknown");
    }
}

void *X_X509_get_key_usage(const X509 *x)
{
    return X509_get_ext_d2i(x, NID_key_usage, NULL, NULL);
}

void X_ASN1_BIT_STRING_free(void *bs)
{
    ASN1_BIT_STRING_free((ASN1_BIT_STRING *)bs);
}

void *X_X509_get_eku(const X509 *x)
{
    return X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL);
}

void X_EXTENDED_KEY_USAGE_free(void *sk)
{
    EXTENDED_KEY_USAGE_free((EXTENDED_KEY_USAGE *)sk);
}

int X_EXTENDED_KEY_USAGE_num(const void *sk)
{
    return sk_ASN1_OBJECT_num((const EXTENDED_KEY_USAGE *)sk);
}

void *X_EXTENDED_KEY_USAGE_value(const void *sk, int i)
{
    return sk_ASN1_OBJECT_value((const EXTENDED_KEY_USAGE *)sk, i);
}

char *X_OBJ_to_string(const void *o)
{
    const ASN1_OBJECT *obj = (const ASN1_OBJECT *)o;
    int nid = OBJ_obj2nid(obj);
    if (nid != NID_undef) {
        const char *sn = OBJ_nid2sn(nid);
        if (sn != NULL)
            return OPENSSL_strdup(sn);
    }
    char buf[256];
    if (OBJ_obj2txt(buf, sizeof(buf), obj, 1) < 0)
        return NULL;
    return OPENSSL_strdup(buf);
}

void *X_X509_get_basic_constraints(const X509 *x)
{
    return X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);
}

void X_BASIC_CONSTRAINTS_free(void *bc)
{
    BASIC_CONSTRAINTS_free((BASIC_CONSTRAINTS *)bc);
}

int X_BASIC_CONSTRAINTS_ca(const void *bc)
{
    const BASIC_CONSTRAINTS *b = (const BASIC_CONSTRAINTS *)bc;
    if (b == NULL)
        return 0;
    return b->ca;
}

long X_BASIC_CONSTRAINTS_pathlen(const void *bc)
{
    const BASIC_CONSTRAINTS *b = (const BASIC_CONSTRAINTS *)bc;
    if (b == NULL || b->pathlen == NULL)
        return -1;
    return ASN1_INTEGER_get(b->pathlen);
}

void *X_sk_X509_EXTENSION_new_null(void)
{
    return sk_X509_EXTENSION_new_null();
}

int X_sk_X509_EXTENSION_push(void *sk, void *ext)
{
    return sk_X509_EXTENSION_push((STACK_OF(X509_EXTENSION) *)sk,
                                  (X509_EXTENSION *)ext);
}

void X_sk_X509_EXTENSION_free(void *sk)
{
    sk_X509_EXTENSION_free((STACK_OF(X509_EXTENSION) *)sk);
}

void X_sk_X509_EXTENSION_pop_free(void *sk)
{
    sk_X509_EXTENSION_pop_free((STACK_OF(X509_EXTENSION) *)sk,
                               X509_EXTENSION_free);
}

int X_sk_X509_EXTENSION_num(const void *sk)
{
    return sk_X509_EXTENSION_num((const STACK_OF(X509_EXTENSION) *)sk);
}

void *X_sk_X509_EXTENSION_value(const void *sk, int i)
{
    return sk_X509_EXTENSION_value((const STACK_OF(X509_EXTENSION) *)sk, i);
}

int X_X509_REQ_add_extensions(X509_REQ *r, void *sk)
{
    return X509_REQ_add_extensions(r, (STACK_OF(X509_EXTENSION) *)sk);
}

void *X_X509_REQ_get_extensions(X509_REQ *r)
{
    return X509_REQ_get_extensions(r);
}

int X_X509_REQ_set_challenge_password(X509_REQ *r, const char *pwd)
{
    /* MBSTRING_UTF8：pwd 来自 Go string（UTF-8），用 MBSTRING_ASC 会把每个
     * 字节当成 Latin-1 字符再编码一次，非 ASCII 口令变成 mojibake。 */
    return X509_REQ_add1_attr_by_NID(r, NID_pkcs9_challengePassword,
                                     MBSTRING_UTF8,
                                     (const unsigned char *)pwd, -1);
}

char *X_X509_REQ_get_challenge_password(X509_REQ *r)
{
    int loc = X509_REQ_get_attr_by_NID(r, NID_pkcs9_challengePassword, -1);
    if (loc < 0)
        return NULL;
    X509_ATTRIBUTE *attr = X509_REQ_get_attr(r, loc);
    if (attr == NULL)
        return NULL;
    ASN1_TYPE *t = X509_ATTRIBUTE_get0_type(attr, 0);
    if (t == NULL)
        return NULL;
    unsigned char *out = NULL;
    int n = ASN1_STRING_to_UTF8(&out, t->value.asn1_string);
    if (n < 0)
        return NULL;
    return (char *)out;
}

void *X_sk_X509_new_null(void)
{
    return sk_X509_new_null();
}

int X_sk_X509_push(void *sk, void *x)
{
    return sk_X509_push((STACK_OF(X509) *)sk, (X509 *)x);
}

void X_sk_X509_free(void *sk)
{
    sk_X509_free((STACK_OF(X509) *)sk);
}

void X_sk_X509_pop_free(void *sk)
{
    sk_X509_pop_free((STACK_OF(X509) *)sk, X509_free);
}

int X_sk_X509_num(const void *sk)
{
    return sk_X509_num((const STACK_OF(X509) *)sk);
}

void *X_sk_X509_value(const void *sk, int i)
{
    return sk_X509_value((const STACK_OF(X509) *)sk, i);
}

void X_X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, void *sk)
{
    X509_STORE_CTX_set0_untrusted(ctx, (STACK_OF(X509) *)sk);
}

int X_sk_X509_REVOKED_num(const void *sk)
{
    return sk_X509_REVOKED_num((const STACK_OF(X509_REVOKED) *)sk);
}

void *X_sk_X509_REVOKED_value(const void *sk, int i)
{
    return sk_X509_REVOKED_value((const STACK_OF(X509_REVOKED) *)sk, i);
}

void X_ASN1_ENUMERATED_free(void *a)
{
    ASN1_ENUMERATED_free((ASN1_ENUMERATED *)a);
}

/* ---------- TLS 密码套件枚举与访问（Tongsuo/OpenSSL 3.x） ---------- */

void *X_SSL_CIPHER_get_name(const void *cipher)
{
    const char *p = SSL_CIPHER_get_name((const SSL_CIPHER *)cipher);
    return p == NULL ? NULL : (void *)OPENSSL_strdup(p);
}

uint32_t X_SSL_CIPHER_get_id(const void *cipher)
{
    return (uint32_t)SSL_CIPHER_get_id((const SSL_CIPHER *)cipher);
}

uint16_t X_SSL_CIPHER_get_protocol_id(const void *cipher)
{
    return (uint16_t)SSL_CIPHER_get_protocol_id((const SSL_CIPHER *)cipher);
}

void *X_SSL_CIPHER_get_version_str(const void *cipher)
{
    const char *p = SSL_CIPHER_get_version((const SSL_CIPHER *)cipher);
    return p == NULL ? NULL : (void *)OPENSSL_strdup(p);
}

void *X_SSL_CTX_get_ciphers(const void *ctx)
{
    return (void *)SSL_CTX_get_ciphers((const SSL_CTX *)ctx);
}

int X_SSL_CIPHER_sk_num(const void *sk)
{
    return sk_SSL_CIPHER_num((const STACK_OF(SSL_CIPHER) *)sk);
}

void *X_SSL_CIPHER_sk_value(const void *sk, int i)
{
    return (void *)sk_SSL_CIPHER_value((const STACK_OF(SSL_CIPHER) *)sk, i);
}

int X_SSL_CTX_set_ciphersuites(void *ctx, const char *str)
{
    return SSL_CTX_set_ciphersuites((SSL_CTX *)ctx, str);
}

void *X_SSL_get_peer_cert_chain(const void *ssl)
{
    return (void *)SSL_get_peer_cert_chain((const SSL *)ssl);
}

int X_ERR_get_lib(uint64_t code)
{
    return (int)ERR_GET_LIB((unsigned long)code);
}

int X_ERR_get_reason(uint64_t code)
{
    return (int)ERR_GET_REASON((unsigned long)code);
}

X509_CRL *X_PEM_read_bio_X509_CRL(BIO *bp)
{
    return PEM_read_bio_X509_CRL(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x)
{
    return PEM_write_bio_X509_CRL(bp, x);
}

/*
 * X_X509_CRL_get_akid_keyid 取出 CRL 的 AuthorityKeyIdentifier 扩展 keyid 字节。
 *
 * 实现要点（OpenSSL 3.x / Tongsuo 8.5+）：
 *   X509_CRL_get_ext_d2i 返回的 AUTHORITY_KEYID 必须由 AUTHORITY_KEYID_free 释放；
 *   而 AUTHORITY_KEYID.keyid 指向的 ASN1_OCTET_STRING 的 data 缓冲会被该 free 一并
 *   释放，因此不能直接返回 akid->keyid 的内部指针（use-after-free）。
 *   这里先 CRYPTO_malloc 一块独立缓冲 memcpy，再 AUTHORITY_KEYID_free，最后返回
 *   CRYPTO_malloc 出来的指针——调用方必须通过 X_OPENSSL_free 释放。
 *
 * out_len 非 NULL 时写入 keyid 字节长度；crl 异常或提取失败返回 NULL。
 */
unsigned char *X_X509_CRL_get_akid_keyid(X509_CRL *crl, int *out_len)
{
    if (crl == NULL || out_len == NULL)
        return NULL;
    AUTHORITY_KEYID *akid = (AUTHORITY_KEYID *)X509_CRL_get_ext_d2i(
        crl, NID_authority_key_identifier, NULL, NULL);
    if (akid == NULL) {
        *out_len = 0;
        return NULL;
    }
    if (akid->keyid == NULL) {
        /* akid 结构本身已分配但无 keyid 字段，仍须释放以免泄漏。 */
        AUTHORITY_KEYID_free(akid);
        *out_len = 0;
        return NULL;
    }
    int len = ASN1_STRING_length((ASN1_STRING *)akid->keyid);
    const unsigned char *src = ASN1_STRING_get0_data((ASN1_STRING *)akid->keyid);
    /* CRYPTO_malloc 与 X_OPENSSL_free 配对使用，绕过 AUTHORITY_KEYID_free 对
     * akid->keyid 内部 data 缓冲的副作用（OpenSSL 3.x 中 ASN1_STRING_free 会
     * 释放该缓冲，导致 memcpy 之后再返回原指针变为 use-after-free）。 */
    unsigned char *buf = (unsigned char *)CRYPTO_malloc((size_t)len, NULL, 0);
    if (buf == NULL) {
        AUTHORITY_KEYID_free(akid);
        *out_len = 0;
        return NULL;
    }
    if (len > 0)
        memcpy(buf, src, (size_t)len);
    AUTHORITY_KEYID_free(akid);
    *out_len = len;
    return buf;
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_rsa(int bits)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)bits);
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_ec(const char *curve)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "EC", (char *)curve);
}

static int X_PEM_pass_cb(char *buf, int size, int rwflag, void *u)
{
    const char *pass = (const char *)u;
    if (pass == NULL)
        return 0;
    int n = (int)strlen(pass);
    if (n > size)
        n = size;
    memcpy(buf, pass, n);
    /* 注意：不要 cleanse buf——OpenSSL 在 cb 返回后还会读取 buf 的前 n 字节
     * 用作解密口令，立即清零会让 OpenSSL 解密失败。
     * OpenSSL 自身负责 buf 的生命周期（其内部的 umem / stack 缓冲会随
     * PEM 解析结束被覆盖或释放）；本回调专注于"复制口令"，不干预后续。
     * 对 Go 侧 C.CString 拷贝的清零应在调用方控制，参见 native.Cleanse。 */
    return n;
}

EVP_PKEY *X_PEM_read_bio_PrivateKey_pass(BIO *bp, const char *pass)
{
    return PEM_read_bio_PrivateKey(bp, NULL, X_PEM_pass_cb, (void *)pass);
}

int X_PEM_write_bio_PrivateKey_enc(BIO *bp, EVP_PKEY *x, const char *pass)
{
    return PEM_write_bio_PrivateKey(bp, x, EVP_aes_256_cbc(), NULL, 0,
                                    X_PEM_pass_cb, (void *)pass);
}

/*
 * X_PEM_write_bio_PrivateKey_enc_cipher 与 X_PEM_write_bio_PrivateKey_enc
 * 同义，多带一个 cipher 名称参数（NULL 兜底 EVP_aes_256_cbc()，保持向后兼容）。
 *
 * 可 cipher 由 OpenSSL EVP_get_cipherbyname 解析，常见名：
 *   aes-128-cbc / aes-192-cbc / aes-256-cbc / des-ede3-cbc / des-cbc 等。
 * 不识别的 cipher 名直接拒绝（NULL 由 EVP_get_cipherbyname 返回 → 返回 0）。
 *
 * 注意：仅适用于 PKCS#8 PBES2 支持的传统 / AEAD cipher。当前依赖 OpenSSL
 * 默认 provider；AES-GCM 等不适用 PBES2 的 cipher 会返回 0，由调用方捕获。
 */
int X_PEM_write_bio_PrivateKey_enc_cipher(BIO *bp, EVP_PKEY *x,
                                          const char *cipher, const char *pass)
{
    const EVP_CIPHER *c = NULL;
    if (cipher != NULL && cipher[0] != '\0') {
        c = EVP_get_cipherbyname(cipher);
        if (c == NULL)
            return 0;
    }
    if (c == NULL)
        c = EVP_aes_256_cbc();
    return PEM_write_bio_PrivateKey(bp, x, c, NULL, 0,
                                    X_PEM_pass_cb, (void *)pass);
}

RSA *X_PEM_read_bio_RSAPrivateKey(BIO *bp)
{
    return PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *rsa)
{
    return PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);
}

PKCS12 *X_PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey,
                        X509 *cert, void **ca, int ca_len)
{
    STACK_OF(X509) *ca_sk = NULL;
    if (ca_len > 0) {
        ca_sk = sk_X509_new_null();
        if (ca_sk == NULL)
            return NULL;
        X509 **arr = (X509 **)ca;
        for (int i = 0; i < ca_len; i++) {
            /* sk_X509_push 在 OpenSSL 3 返回压入后的栈长度而非 0/1，
             * 故这里判断 <= 0（失败时返回 0）。 */
            if (arr[i] == NULL || sk_X509_push(ca_sk, arr[i]) <= 0) {
                sk_X509_free(ca_sk);
                return NULL;
            }
        }
    }
    PKCS12 *p12 = PKCS12_create(pass, name, pkey, cert, ca_sk,
                                NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                2048, 2048, 0);
    if (ca_sk != NULL)
        sk_X509_free(ca_sk); /* 栈元素为借用指针，仅释放数组 */
    return p12;
}

int X_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey,
                   X509 **cert, void **ca)
{
    STACK_OF(X509) *ca_sk = NULL;
    int ok = PKCS12_parse(p12, pass, pkey, cert, &ca_sk);
    if (ca != NULL)
        *ca = ca_sk;
    return ok;
}

void *X_PKCS7_get0_certificates(PKCS7 *p7)
{
    if (p7 == NULL || OBJ_obj2nid(p7->type) != NID_pkcs7_signed)
        return NULL;
    return p7->d.sign->cert;
}

int X_OCSP_basic_verify(OCSP_BASICRESP *bs, void *certs, X509_STORE *st,
                        unsigned long flags)
{
    return OCSP_basic_verify(bs, (STACK_OF(X509) *)certs, st, flags);
}

/*
 * X_EVP_KDF_HKDF：一次性 HKDF（RFC 5869）派生。
 * mode 取 EVP_KDF_HKDF_MODE_*（0=extract-and-expand）。key/salt/info 为空时
 * 对应参数不设置（extract-and-expand 缺 salt 视为全零盐）。
 */
int X_EVP_KDF_HKDF(const char *digest, int mode,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *salt, size_t salt_len,
                   const unsigned char *info, size_t info_len,
                   unsigned char *out, size_t out_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[6];
    int idx = 0;
    int ok = 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL)
        goto end;
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
        goto end;
    if (digest != NULL)
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, (char *)digest, 0);
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    if (key != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, (void *)key, key_len);
    if (salt != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    if (info != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[idx] = OSSL_PARAM_construct_end();
    ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
end:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

/*
 * X_EVP_KDF_PBKDF2：一次性 PBKDF2（RFC 8018）派生。
 * iter 为迭代次数；pass 为空时参数不设置（provider 侧将报错）。
 */
int X_EVP_KDF_PBKDF2(const char *digest,
                     const unsigned char *pass, size_t pass_len,
                     const unsigned char *salt, size_t salt_len,
                     int iter,
                     unsigned char *out, size_t out_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    int idx = 0;
    int ok = 0;

    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (kdf == NULL)
        goto end;
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
        goto end;
    if (digest != NULL)
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, (char *)digest, 0);
    if (pass != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, (void *)pass, pass_len);
    if (salt != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iter);
    params[idx] = OSSL_PARAM_construct_end();
    ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
end:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

int X_EVP_KDF_available(const char *algorithm)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, algorithm, NULL);
    if (kdf == NULL) {
        ERR_clear_error();
        return 0;
    }
    EVP_KDF_free(kdf);
    return 1;
}

/*
 * X_EVP_KDF_derive：按算法名 fetch KDF 并一次性派生。
 * 各算法的 OSSL_PARAM 集合差异很大，这里按 alg 分支组装参数数组。
 * 返回 1 成功，0 失败（错误已入队列）。
 */
int X_EVP_KDF_derive(const char *alg, const X_KDF_PARAMS *p,
                     unsigned char *out, size_t out_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[16];
    int idx = 0;
    int ok = 0;
    int mode = 0;
    uint64_t iter64 = 0;
    int use_l = 0, use_separator = 0, use_keybits = 0;

    if (alg == NULL || p == NULL)
        return 0;

    kdf = EVP_KDF_fetch(NULL, alg, NULL);
    if (kdf == NULL)
        goto end;
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL)
        goto end;

    if (strcmp(alg, "HKDF") == 0) {
        mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->key != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY, (void *)p->key, p->keylen);
        if (p->salt != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)p->salt, p->saltlen);
        if (p->info != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO, (void *)p->info, p->infolen);
    } else if (strcmp(alg, "PBKDF2") == 0) {
        iter64 = p->iter;
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->pass != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD, (void *)p->pass, p->passlen);
        if (p->salt != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)p->salt, p->saltlen);
        params[idx++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER,
                                                    &iter64);
    } else if (strcmp(alg, "SCRYPT") == 0) {
        uint64_t n = p->n, r = p->r, pp = p->p, maxmem = p->maxmem;

        if (p->pass != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD, (void *)p->pass, p->passlen);
        if (p->salt != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)p->salt, p->saltlen);
        params[idx++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n);
        params[idx++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, &r);
        params[idx++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P, &pp);
        /* maxmem 为 0 表示不下传，让 provider 使用其默认值。 */
        /* A zero maxmem means "not supplied", letting the provider default apply. */
        if (p->maxmem != 0)
            params[idx++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM,
                                                        &maxmem);
    } else if (strcmp(alg, "SSKDF") == 0) {
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->secret != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET, (void *)p->secret, p->secretlen);
        if (p->key != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY, (void *)p->key, p->keylen);
        if (p->salt != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)p->salt, p->saltlen);
        if (p->info != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO, (void *)p->info, p->infolen);
    } else if (strcmp(alg, "TLS1-PRF") == 0) {
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->secret != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET, (void *)p->secret, p->secretlen);
        if (p->seed != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SEED, (void *)p->seed, p->seedlen);
    } else if (strcmp(alg, "TLS13-KDF") == 0) {
        /*
         * TLS13-KDF 只支持 EXTRACT_ONLY 与 EXPAND_ONLY 两种模式，
         * 不支持 HKDF 的 EXTRACT_AND_EXPAND。
         */
        mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
        if (p->mode != NULL && OPENSSL_strcasecmp(p->mode, "EXPAND_ONLY") == 0)
            mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
        else if (p->mode != NULL && OPENSSL_strcasecmp(p->mode, "EXTRACT_ONLY") == 0)
            mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
        else if (p->mode != NULL && p->mode[0] != '\0')
            goto end;
        params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->key != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY, (void *)p->key, p->keylen);
        if (p->salt != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)p->salt, p->saltlen);
        if (p->label != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_LABEL, (void *)p->label, p->labellen);
        if (p->prefix != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PREFIX, (void *)p->prefix, p->prefixlen);
        if (p->data != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_DATA, (void *)p->data, p->datalen);
    } else if (strcmp(alg, "KBKDF") == 0) {
        int r_int = (int)p->r;

        use_l = p->use_l;
        use_separator = p->use_separator;
        if (p->mode != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_MODE, (char *)p->mode, 0);
        if (p->mac != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_MAC, (char *)p->mac, 0);
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->key != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY, (void *)p->key, p->keylen);
        if (p->salt != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)p->salt, p->saltlen);
        if (p->info != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO, (void *)p->info, p->infolen);
        /*
         * KBKDF 的计数器宽度参数 r 是 OpenSSL 3.2+ 才有的；Tongsuo 8.4.0
         * （OpenSSL 3.0.3 底座，CI 固定版本）没有该参数，下传会让 provider
         * 报 "Parameter unknown"。未定义时直接略过，此时 R 取 provider 默认值。
         * The KBKDF counter-width parameter r only exists in OpenSSL 3.2+;
         * Tongsuo 8.4.0 (OpenSSL 3.0.3 base, the CI pin) lacks it and would
         * reject the parameter. When the macro is missing the parameter is
         * simply omitted and R falls back to the provider default.
         */
#ifdef OSSL_KDF_PARAM_KBKDF_R
        if (p->r != 0)
            params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R,
                                                     &r_int);
#else
        (void)r_int;
#endif
        params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L,
                                                 &use_l);
        params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR,
                                                 &use_separator);
    } else if (strcmp(alg, "X942KDF-ASN1") == 0) {
        use_keybits = p->use_keybits;
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->secret != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET, (void *)p->secret, p->secretlen);
        if (p->key != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY, (void *)p->key, p->keylen);
        if (p->ukm != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_UKM, (void *)p->ukm, p->ukmlen);
        if (p->cekalg != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_CEK_ALG, (char *)p->cekalg, 0);
        /*
         * use-keybits 的 provider 默认值为 1；只有显式启用时才下传，
         * 避免用 0 覆盖默认值（那会改变 OtherInfo 的构成）。
         * The provider default for use-keybits is 1; the parameter is only
         * forwarded when explicitly enabled so that an implicit zero does
         * not override the default (which would change OtherInfo).
         */
        if (use_keybits != 0)
            params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_X942_USE_KEYBITS,
                                                    &use_keybits);
    } else if (strcmp(alg, "X963KDF") == 0) {
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->secret != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET, (void *)p->secret, p->secretlen);
        if (p->key != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY, (void *)p->key, p->keylen);
        if (p->info != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO, (void *)p->info, p->infolen);
    } else if (strcmp(alg, "HMAC-DRBG-KDF") == 0) {
        /*
         * HMAC-DRBG-KDF 及其 entropy / nonce 参数在 Tongsuo 8.4.0
         * （OpenSSL 3.0.3 底座）不存在，那类构建直接拒绝。
         * HMAC-DRBG-KDF and its entropy / nonce parameters do not exist in
         * Tongsuo 8.4.0 (OpenSSL 3.0.3 base); such builds are rejected here.
         */
#ifdef OSSL_KDF_PARAM_HMACDRBG_ENTROPY
        if (p->digest != NULL)
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST, (char *)p->digest, 0);
        if (p->entropy != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_HMACDRBG_ENTROPY, (void *)p->entropy,
                p->entropylen);
        if (p->nonce != NULL)
            params[idx++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_HMACDRBG_NONCE, (void *)p->nonce, p->noncelen);
#else
        goto end;
#endif
    } else {
        goto end;
    }

    params[idx] = OSSL_PARAM_construct_end();
    ok = EVP_KDF_derive(ctx, out, out_len, params) == 1;
end:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

/*
 * X_EVP_MAC_CTX_set_params：按 mask 组装 OSSL_PARAM 并设置到 MAC 上下文。
 * 返回 1 成功，0 失败（错误已入队列）。
 */
int X_EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, int mask,
                             const char *cipher, const char *digest,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *custom, size_t custom_len,
                             size_t size)
{
    OSSL_PARAM params[6];
    int idx = 0;

    if (ctx == NULL)
        return 0;

    if ((mask & X_MAC_OPT_CIPHER) && cipher != NULL)
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_CIPHER, (char *)cipher, 0);
    if ((mask & X_MAC_OPT_DIGEST) && digest != NULL)
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, (char *)digest, 0);
    if ((mask & X_MAC_OPT_IV) && iv != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_IV, (void *)iv, iv_len);
    if ((mask & X_MAC_OPT_CUSTOM) && custom != NULL)
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM, (void *)custom, custom_len);
    if (mask & X_MAC_OPT_SIZE)
        params[idx++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE,
                                                    &size);
    params[idx] = OSSL_PARAM_construct_end();
    return EVP_MAC_CTX_set_params(ctx, params);
}

/*
 * 可增长字符串缓冲：算法枚举结果用 '\n' 分隔累积。
 */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} X_STRBUF;

static int x_strbuf_append(X_STRBUF *sb, const char *s)
{
    size_t n;

    if (s == NULL)
        return 1;
    n = strlen(s);
    if (sb->len + n + 2 > sb->cap) {
        size_t ncap = sb->cap ? sb->cap : 256;
        char *nb;

        while (ncap < sb->len + n + 2)
            ncap *= 2;
        nb = OPENSSL_realloc(sb->buf, ncap);
        if (nb == NULL)
            return 0;
        sb->buf = nb;
        sb->cap = ncap;
    }
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len++] = '\n';
    sb->buf[sb->len] = '\0';
    return 1;
}

static void x_collect_md(EVP_MD *md, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_MD_get0_name(md);

    if (name == NULL)
        return;
    {
        EVP_MD *impl = EVP_MD_fetch(NULL, name, NULL);

        if (impl == NULL) {
            ERR_clear_error();
            return;
        }
        EVP_MD_free(impl);
    }
    x_strbuf_append(sb, name);
}

static void x_collect_cipher(EVP_CIPHER *cipher, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_CIPHER_get0_name(cipher);

    if (name == NULL)
        return;
    {
        EVP_CIPHER *impl = EVP_CIPHER_fetch(NULL, name, NULL);

        if (impl == NULL) {
            ERR_clear_error();
            return;
        }
        EVP_CIPHER_free(impl);
    }
    x_strbuf_append(sb, name);
}

static void x_collect_mac(EVP_MAC *mac, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_MAC_get0_name(mac);

    if (name == NULL)
        return;
    {
        EVP_MAC *impl = EVP_MAC_fetch(NULL, name, NULL);

        if (impl == NULL) {
            ERR_clear_error();
            return;
        }
        EVP_MAC_free(impl);
    }
    x_strbuf_append(sb, name);
}

static void x_collect_kdf(EVP_KDF *kdf, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_KDF_get0_name(kdf);

    if (name == NULL)
        return;
    {
        EVP_KDF *impl = EVP_KDF_fetch(NULL, name, NULL);

        if (impl == NULL) {
            ERR_clear_error();
            return;
        }
        EVP_KDF_free(impl);
    }
    x_strbuf_append(sb, name);
}

static void x_collect_signature(EVP_SIGNATURE *sig, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_SIGNATURE_get0_name(sig);

    if (name != NULL)
        x_strbuf_append(sb, name);
}

static void x_collect_keyexch(EVP_KEYEXCH *keyexch, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_KEYEXCH_get0_name(keyexch);

    if (name != NULL)
        x_strbuf_append(sb, name);
}

static void x_collect_kem(EVP_KEM *kem, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    const char *name = EVP_KEM_get0_name(kem);

    if (name != NULL)
        x_strbuf_append(sb, name);
}

/*
 * X_EVP_alg_names：枚举当前已加载 provider 提供的算法规范名。
 * 返回以 '\n' 分隔的 OPENSSL_malloc 字符串；无元素时返回 NULL。
 */
char *X_EVP_alg_names(int kind)
{
    X_STRBUF sb;

    memset(&sb, 0, sizeof(sb));
    switch (kind) {
    case X_ALG_KIND_MD:
        EVP_MD_do_all_provided(NULL, x_collect_md, &sb);
        break;
    case X_ALG_KIND_CIPHER:
        EVP_CIPHER_do_all_provided(NULL, x_collect_cipher, &sb);
        break;
    case X_ALG_KIND_MAC:
        EVP_MAC_do_all_provided(NULL, x_collect_mac, &sb);
        break;
    case X_ALG_KIND_KDF:
        EVP_KDF_do_all_provided(NULL, x_collect_kdf, &sb);
        break;
    case X_ALG_KIND_SIGNATURE:
        EVP_SIGNATURE_do_all_provided(NULL, x_collect_signature, &sb);
        break;
    case X_ALG_KIND_KEYEXCH:
        EVP_KEYEXCH_do_all_provided(NULL, x_collect_keyexch, &sb);
        break;
    case X_ALG_KIND_KEM:
        EVP_KEM_do_all_provided(NULL, x_collect_kem, &sb);
        break;
    default:
        return NULL;
    }
    if (sb.len == 0) {
        OPENSSL_free(sb.buf);
        return NULL;
    }
    return sb.buf;
}

/*
 * X_OSSL_provider_list：列出活跃 provider 的名称 / 版本 / 状态。
 * 每行 "<name>\t<version>\t<status>"，以 '\n' 分隔。
 * name 取 OSSL_PROVIDER_get0_name 的短名（如 "default"），与
 * `openssl list -providers` 的首行一致。
 */
static int x_collect_provider(OSSL_PROVIDER *prov, void *arg)
{
    X_STRBUF *sb = (X_STRBUF *)arg;
    OSSL_PARAM params[4];
    char *version = NULL;
    int status = 0;
    const char *name = OSSL_PROVIDER_get0_name(prov);
    char line[512];

    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION,
                                               &version, 0);
    params[1] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, &status);
    params[2] = OSSL_PARAM_construct_end();
    if (!OSSL_PROVIDER_get_params(prov, params))
        return 1;
    BIO_snprintf(line, sizeof(line), "%s\t%s\t%s",
                 name != NULL ? name : "",
                 version != NULL ? version : "",
                 status ? "active" : "inactive");
    x_strbuf_append(sb, line);
    return 1;
}

char *X_OSSL_provider_list(void)
{
    X_STRBUF sb;

    memset(&sb, 0, sizeof(sb));
    if (!OSSL_PROVIDER_do_all(NULL, x_collect_provider, &sb)) {
        OPENSSL_free(sb.buf);
        return NULL;
    }
    if (sb.len == 0) {
        OPENSSL_free(sb.buf);
        return NULL;
    }
    return sb.buf;
}

const char *X_OPENSSL_seed_source(void)
{
    return OPENSSL_info(OPENSSL_INFO_SEED_SOURCE);
}

/*
 * X_SSL_group_names：列出本机构建的 TLS 组名。
 * 与 `openssl list -tls-groups` 同口径：探测 ctx 限定 min=max=TLS1.3
 * （本机构建未启用 TLS 1.3 时退化为 TLS 1.2），并按 group_id 去重
 * （对应 CLI 的 all=0）。
 */
char *X_SSL_group_names(void)
{
    SSL_CTX *ctx = NULL;
    STACK_OF(OPENSSL_CSTRING) *groups = NULL;
    X_STRBUF sb;
    size_t i, num;

    memset(&sb, 0, sizeof(sb));
    groups = sk_OPENSSL_CSTRING_new_null();
    if (groups == NULL)
        return NULL;
    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto err;
#ifdef TLS1_3_VERSION
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        /* 本机构建未启用 TLS 1.3，退化为 TLS 1.2。 */
        SSL_CTX_free(ctx);
        ctx = SSL_CTX_new(TLS_method());
        if (ctx == NULL)
            goto err;
        if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)
                || !SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION))
            goto err;
    }
#else
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)
            || !SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION))
        goto err;
#endif
#if OPENSSL_VERSION_NUMBER < 0x30200000L
    /*
     * SSL_CTX_get0_implemented_groups 是 OpenSSL 3.2+ 的接口；
     * Tongsuo 8.4.0（OpenSSL 3.0.3 底座，CI 固定版本）没有它，
     * 此时返回空列表，由上层表现为「本构建不支持枚举 TLS 组」。
     * SSL_CTX_get0_implemented_groups is an OpenSSL 3.2+ API. Tongsuo
     * 8.4.0 (OpenSSL 3.0.3 base, the CI pin) lacks it; an empty list is
     * returned instead and the caller sees "group enumeration not
     * supported by this build".
     */
    sk_OPENSSL_CSTRING_free(groups);
    SSL_CTX_free(ctx);
    OPENSSL_free(sb.buf);
    return NULL;
#else
    if (!SSL_CTX_get0_implemented_groups(ctx, 0, groups))
        goto err;
    num = sk_OPENSSL_CSTRING_num(groups);
    for (i = 0; i < num; i++) {
        const char *g = sk_OPENSSL_CSTRING_value(groups, (int)i);

        if (g != NULL)
            x_strbuf_append(&sb, g);
    }
    sk_OPENSSL_CSTRING_free(groups);
    SSL_CTX_free(ctx);
    if (sb.len == 0) {
        OPENSSL_free(sb.buf);
        return NULL;
    }
    return sb.buf;
#endif
err:
    sk_OPENSSL_CSTRING_free(groups);
    SSL_CTX_free(ctx);
    OPENSSL_free(sb.buf);
    return NULL;
}

/*
 * X_SSL_groups_supported：报告本构建是否支持枚举 TLS 组。
 * SSL_CTX_get0_implemented_groups 是 OpenSSL 3.2+ 接口；Tongsuo 8.4.0
 * （OpenSSL 3.0.3 底座）没有它，此时 X_SSL_group_names 返回空列表。
 *
 * X_SSL_groups_supported reports whether this build can enumerate TLS
 * groups. SSL_CTX_get0_implemented_groups is an OpenSSL 3.2+ API and
 * Tongsuo 8.4.0 (OpenSSL 3.0.3 base) lacks it, in which case
 * X_SSL_group_names returns an empty list.
 */
int X_SSL_groups_supported(void)
{
#if OPENSSL_VERSION_NUMBER < 0x30200000L
    return 0;
#else
    return 1;
#endif
}

/*
 * X_EVP_KDF_kbkdf_r_supported：报告本构建的 KBKDF 是否接受 r 参数。
 * OSSL_KDF_PARAM_KBKDF_R 是 OpenSSL 3.2+ 才有的参数名。
 *
 * X_EVP_KDF_kbkdf_r_supported reports whether this build's KBKDF accepts
 * the r parameter. OSSL_KDF_PARAM_KBKDF_R only exists in OpenSSL 3.2+.
 */
int X_EVP_KDF_kbkdf_r_supported(void)
{
#ifdef OSSL_KDF_PARAM_KBKDF_R
    return 1;
#else
    return 0;
#endif
}
