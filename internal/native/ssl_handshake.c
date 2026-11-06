#include "ssl_handshake.h"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <string.h>
extern void CgoTLSRelease(uintptr_t);
extern int CgoTLSSelect(uintptr_t, SSL *, char *, int);
extern int CgoTLSVerify(uintptr_t, int, int, int, X509 *);
extern int CgoTLSALPN(uintptr_t, unsigned char *, unsigned int);
/* Only an integer cgo.Handle ID crosses the lifetime boundary into C.
 * Pending write data is copied into native memory and retained across retries.
 * Go's core layer serializes all access to an SSL and its hooks. */
typedef struct {
    uintptr_t id;
    unsigned char *writebuf;
    int writelen;
} tls_hooks;
static int hooks_index = -1;
static CRYPTO_ONCE hooks_once = CRYPTO_ONCE_STATIC_INIT;
static void hooks_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    tls_hooks *hooks = ptr;
    if (hooks == NULL)
        return;
    CgoTLSRelease(hooks->id);
    OPENSSL_clear_free(hooks->writebuf, hooks->writelen);
    OPENSSL_free(hooks);
}
static void hooks_init(void) { hooks_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, hooks_free); }
static uintptr_t hooks_id(SSL *ssl) {
    if (!CRYPTO_THREAD_run_once(&hooks_once, hooks_init) || hooks_index < 0) return 0;
    tls_hooks *hooks = SSL_get_ex_data(ssl, hooks_index);
    return hooks ? hooks->id : 0;
}
static int verify_cb(int ok, X509_STORE_CTX *store) {
    SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    uintptr_t id = hooks_id(ssl);
    if (!id) return ok;
    return CgoTLSVerify(id, ok, X509_STORE_CTX_get_error(store),
                        X509_STORE_CTX_get_error_depth(store), X509_STORE_CTX_get_current_cert(store));
}
static int hello_cb(SSL *ssl, int *alert, void *unused) {
    uintptr_t id = hooks_id(ssl);
    if (!id) return SSL_CLIENT_HELLO_SUCCESS;
    const unsigned char *ext = NULL;
    size_t len = 0;
    char *name = NULL;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &ext, &len)) {
        if (len < 5 || (((size_t)ext[0] << 8) | ext[1]) != len - 2 || ext[2] != 0) {
            *alert = SSL_AD_DECODE_ERROR; return SSL_CLIENT_HELLO_ERROR;
        }
        size_t n = ((size_t)ext[3] << 8) | ext[4];
        if (n == 0 || n != len - 5 || memchr(ext + 5, 0, n)) {
            *alert = SSL_AD_ILLEGAL_PARAMETER; return SSL_CLIENT_HELLO_ERROR;
        }
        name = OPENSSL_strndup((const char *)ext + 5, n);
        if (!name) { *alert = SSL_AD_INTERNAL_ERROR; return SSL_CLIENT_HELLO_ERROR; }
    }
    int ntls = SSL_client_hello_get0_legacy_version(ssl) == NTLS1_1_VERSION;
    int ok = CgoTLSSelect(id, ssl, name, ntls);
    OPENSSL_free(name);
    if (!ok) { *alert = SSL_AD_INTERNAL_ERROR; return SSL_CLIENT_HELLO_ERROR; }
    return SSL_CLIENT_HELLO_SUCCESS;
}
static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *unused) {
    uintptr_t id = hooks_id(ssl);
    if (!id) return SSL_TLSEXT_ERR_NOACK;
    int offset = CgoTLSALPN(id, (unsigned char *)in, inlen);
    if (offset == -1) return SSL_TLSEXT_ERR_NOACK;
    if (offset < 0 || (unsigned int)offset >= inlen || offset + 1u + in[offset] > inlen) return SSL_TLSEXT_ERR_ALERT_FATAL;
    /* Return a pointer into the caller's C buffer, never into Go memory. */
    *outlen = in[offset];
    *out = in + offset + 1;
    return SSL_TLSEXT_ERR_OK;
}
void X_SSL_CTX_callbacks(SSL_CTX *ctx) {
    SSL_CTX_set_client_hello_cb(ctx, hello_cb, NULL);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, NULL);
}
int X_SSL_attach(SSL *ssl, uintptr_t id) {
    if (!CRYPTO_THREAD_run_once(&hooks_once, hooks_init) || hooks_index < 0) return 0;
    tls_hooks *hooks = OPENSSL_zalloc(sizeof(*hooks));
    if (!hooks) return 0;
    hooks->id = id;
    if (!SSL_set_ex_data(ssl, hooks_index, hooks)) { OPENSSL_free(hooks); return 0; }
    SSL_set_verify(ssl, SSL_get_verify_mode(ssl), verify_cb);
    return 1;
}
int X_SSL_switch_context(SSL *ssl, SSL_CTX *ctx) {
    if (!SSL_set_SSL_CTX(ssl, ctx)) return 0;
    SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx), verify_cb);
    SSL_set_verify_depth(ssl, SSL_CTX_get_verify_depth(ctx));
    if (!SSL_set1_verify_cert_store(ssl, SSL_CTX_get_cert_store(ctx))) return 0;
    STACK_OF(X509_NAME) *names = SSL_CTX_get_client_CA_list(ctx);
    STACK_OF(X509_NAME) *copy = names ? SSL_dup_CA_list(names) : NULL;
    if (names && !copy) return 0;
    SSL_set_client_CA_list(ssl, copy);
    SSL_clear_options(ssl, SSL_get_options(ssl));
    SSL_set_options(ssl, SSL_CTX_get_options(ctx));
    SSL_clear_mode(ssl, SSL_get_mode(ssl));
    SSL_set_mode(ssl, SSL_CTX_get_mode(ctx));
    if (!SSL_set_min_proto_version(ssl, SSL_CTX_get_min_proto_version(ctx)) ||
        !SSL_set_max_proto_version(ssl, SSL_CTX_get_max_proto_version(ctx))) return 0;
    return 1;
}
int X_SSL_CTX_parameters(SSL_CTX *ctx, const char *groups, const char *sigalgs,
                        const unsigned char *dh, size_t dhlen, uint64_t options, long modes) {
    if (*groups && !SSL_CTX_set1_groups_list(ctx, groups)) return 0;
    if (*sigalgs && !SSL_CTX_set1_sigalgs_list(ctx, sigalgs)) return 0;
    if (dhlen) {
        BIO *bio = BIO_new_mem_buf(dh, (int)dhlen);
        if (!bio) return 0;
        EVP_PKEY *params = PEM_read_bio_Parameters(bio, NULL);
        BIO_free(bio);
        if (!params) return 0;
        /* Successful set0 transfers ownership to the context. */
        if (!EVP_PKEY_is_a(params, "DH") || !SSL_CTX_set0_tmp_dh_pkey(ctx, params)) {
            EVP_PKEY_free(params);
            return 0;
        }
    }
    SSL_CTX_set_options(ctx, options);
    SSL_CTX_set_mode(ctx, modes);
    return 1;
}
int X_SSL_CTX_add_chain(SSL_CTX *ctx, X509 *cert) { return SSL_CTX_add1_chain_cert(ctx, cert); }
int X_SSL_CTX_add_client_ca(SSL_CTX *ctx, X509 *cert) { return SSL_CTX_add_client_CA(ctx, cert); }
int X_SSL_set_verify_name(SSL *ssl, const char *host, int ip, unsigned int flags, const char *email) {
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, flags);
    if (*host && !(ip ? X509_VERIFY_PARAM_set1_ip_asc(param, host) : SSL_set1_host(ssl, host))) return 0;
    if (*email && !X509_VERIFY_PARAM_set1_email(param, email, 0)) return 0;
    return 1;
}
int X_SSL_name_check(X509 *cert, const char *name, int kind, unsigned int flags) {
    if (kind == 1) return X509_check_ip_asc(cert, name, flags);
    if (kind == 2) return X509_check_email(cert, name, 0, flags);
    return X509_check_host(cert, name, 0, flags, NULL);
}

int X_SSL_groups(SSL *s, const char *v) { return SSL_set1_groups_list(s,v); }
int X_SSL_sigalgs(SSL *s, const char *v) { return SSL_set1_sigalgs_list(s,v); }
int X_SSL_group(SSL *s) { return SSL_get_negotiated_group(s); }
int X_SSL_peer_sig(SSL *s, int *nid) { return SSL_get_peer_signature_nid(s,nid); }
int X_TLS_chain_num(STACK_OF(X509) *sk) { return sk ? sk_X509_num(sk) : 0; }
X509 *X_TLS_chain_value(STACK_OF(X509) *sk, int i) { return sk_X509_value(sk,i); }

int X_SSL_write_owned(SSL *ssl, const void *buf, int len) {
    tls_hooks *hooks = SSL_get_ex_data(ssl, hooks_index);
    if (!hooks) return -1;
    if (!hooks->writebuf) {
        hooks->writebuf = OPENSSL_memdup(buf, len);
        if (!hooks->writebuf) { ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE); return -1; }
        hooks->writelen = len;
    }
    int ret = SSL_write(ssl, hooks->writebuf, hooks->writelen);
    if (ret > 0) {
        OPENSSL_clear_free(hooks->writebuf, hooks->writelen);
        hooks->writebuf = NULL;
        hooks->writelen = 0;
    }
    return ret;
}
void X_SSL_send_close_notify(SSL *ssl) {
    tls_hooks *hooks = SSL_get_ex_data(ssl, hooks_index);
    if (SSL_is_init_finished(ssl) && (!hooks || !hooks->writebuf)) SSL_shutdown(ssl);
}
