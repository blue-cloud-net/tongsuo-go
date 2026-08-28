#include "shim.h"

#include <string.h>

int X_EVP_Digest(const EVP_MD *md, const unsigned char *data, size_t count,
                 unsigned char *md_out, unsigned int *size)
{
    return EVP_Digest(data, count, md_out, size, md, NULL);
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_sm2(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}

EVP_PKEY *X_PEM_read_bio_PrivateKey(BIO *bp)
{
    return PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
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

int X_X509V3_EXT_conf_nid_ctx(X509 *target, X509 *subject, X509 *issuer,
                              int nid, const char *value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, subject, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ext == NULL)
        return 0;
    int ok = X509_add_ext(target, ext, -1);
    X509_EXTENSION_free(ext);
    return ok;
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
    return X509_REQ_add1_attr_by_NID(r, NID_pkcs9_challengePassword,
                                     MBSTRING_ASC,
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

X509_CRL *X_PEM_read_bio_X509_CRL(BIO *bp)
{
    return PEM_read_bio_X509_CRL(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x)
{
    return PEM_write_bio_X509_CRL(bp, x);
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
            if (arr[i] == NULL || !sk_X509_push(ca_sk, arr[i])) {
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
