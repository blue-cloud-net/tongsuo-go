#include "ssl_handshake.h"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <string.h>
#include <limits.h>
extern void CgoTLSRelease(uintptr_t);
extern int CgoTLSSelect(uintptr_t, SSL *, char *, int);
extern int CgoTLSVerify(uintptr_t, int, int, int, X509 *);
extern int CgoTLSALPN(uintptr_t, unsigned char *, unsigned int);
/* Only an integer cgo.Handle ID crosses the lifetime boundary into C.
 * Pending write data is copied into native memory and retained across retries.
 * Go's core layer serializes all access to an SSL and its hooks. */
typedef struct {
    uintptr_t id;
    int diagnostics;
    size_t diagnostic_limit;
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
static void diagnostic_keylog(const SSL *ssl, const char *line);
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

int X_SSL_groups(SSL *s, const char *v) {
    /* Use the public NID setter: 8.4's string setter leaks the previous list. */
    size_t count = 1;
    for (const char *p = v; *p; ++p) if (*p == ':') ++count;
    if (count > INT_MAX || count > SIZE_MAX / sizeof(int)) return 0;
    int *groups = OPENSSL_malloc(count * sizeof(*groups));
    char *copy = OPENSSL_strdup(v);
    if (!groups || !copy) { OPENSSL_free(groups); OPENSSL_free(copy); return 0; }
    size_t n = 0; char *cursor = copy, *token;
    int ok = 0;
    while ((token = strsep(&cursor, ":")) != NULL) {
        if (!*token) goto done;
        int nid = OBJ_sn2nid(token);
        if (nid == NID_undef) nid = OBJ_ln2nid(token);
        if (nid == NID_undef) nid = EC_curve_nist2nid(token);
        if (nid == NID_undef && !strcmp(token, "curveSM2")) nid = NID_sm2;
        if (nid == NID_undef) goto done;
        groups[n++] = nid;
    }
    ok = SSL_set1_groups(s, groups, (int)n);
done:
    OPENSSL_free(groups); OPENSSL_free(copy); return ok;
}
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

#include <openssl/ct.h>
#include <limits.h>
int X_SSL_CTX_rfc8998(SSL_CTX *ctx) {
#ifndef OPENSSL_NO_SM2
    SSL_CTX_enable_sm_tls13_strict(ctx); return 1;
#else
    return 0;
#endif
}
int X_SSL_rfc8998(SSL *ssl, int enabled) {
#ifndef OPENSSL_NO_SM2
    if (enabled) SSL_enable_sm_tls13_strict(ssl);
    else SSL_disable_sm_tls13_strict(ssl);
    return 1;
#else
    return !enabled;
#endif
}
#ifndef OPENSSL_NO_CT
static int capture_ct(const CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts, void *arg) { return 1; }
#endif
int X_SSL_capture_sct(SSL *ssl) {
#ifndef OPENSSL_NO_CT
    return SSL_set_ct_validation_callback(ssl, capture_ct, NULL);
#else
    return 0;
#endif
}
int X_SSL_secure_renegotiation(SSL *ssl) { return SSL_get_secure_renegotiation_support(ssl) != 0; }
int X_SSL_sct_count(SSL *ssl) {
#ifndef OPENSSL_NO_CT
    const STACK_OF(SCT) *scts = SSL_get0_peer_scts(ssl);
    return scts ? sk_SCT_num(scts) : 0;
#else
    return 0;
#endif
}
int X_SSL_sct_copy(SSL *ssl, int index, unsigned char **out) {
#ifndef OPENSSL_NO_CT
    const STACK_OF(SCT) *scts = SSL_get0_peer_scts(ssl);
    if (!scts || index < 0 || index >= sk_SCT_num(scts)) return -1;
    const SCT *sct = sk_SCT_value(scts, index);
    if (SCT_get_source(sct) != SCT_SOURCE_TLS_EXTENSION) return 0;
    return i2o_SCT(sct, out);
#else
    return -1;
#endif
}
extern size_t CgoTLSTraceBudget(uintptr_t);
extern void CgoTLSObserve(uintptr_t, int, int, int, int, int, void *, size_t);
static tls_hooks *diagnostic_hooks(const SSL *ssl) {
    return hooks_index < 0 ? NULL : SSL_get_ex_data(ssl, hooks_index);
}
#ifndef OPENSSL_NO_SSL_TRACE
typedef struct { unsigned char *data; size_t length, limit; int failed; } trace_buffer;
static int trace_write(BIO *bio, const char *data, int length) {
    trace_buffer *b = BIO_get_data(bio);
    if (length < 0 || (size_t)length > b->limit - b->length) { b->failed = 1; return -1; }
    unsigned char *next = OPENSSL_realloc(b->data, b->length + (size_t)length + 1);
    if (!next) { b->failed = 1; return -1; }
    b->data = next; memcpy(b->data + b->length, data, length); b->length += length;
    return length;
}
static int trace_puts(BIO *bio, const char *text) { return trace_write(bio, text, (int)strlen(text)); }
static long trace_ctrl(BIO *bio, int cmd, long num, void *ptr) { return cmd == BIO_CTRL_FLUSH ? 1 : 0; }
static int trace_create(BIO *bio) { BIO_set_init(bio, 1); return 1; }
static BIO_METHOD *trace_method;
static CRYPTO_ONCE trace_once = CRYPTO_ONCE_STATIC_INIT;
static void trace_init(void) {
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "bounded TLS trace");
    if (!m) return;
    if (!BIO_meth_set_write(m, trace_write) || !BIO_meth_set_puts(m, trace_puts) || !BIO_meth_set_ctrl(m, trace_ctrl) || !BIO_meth_set_create(m, trace_create)) { BIO_meth_free(m); return; }
    trace_method = m;
}
#endif
static void diagnostic_message(int write, int version, int type, const void *buf, size_t length, SSL *ssl, void *unused) {
    tls_hooks *h = diagnostic_hooks(ssl); if (!h) return;
    if (h->diagnostics & 1) CgoTLSObserve(h->id, 3, write, version, type, 0, (void *)buf, length);
#ifndef OPENSSL_NO_SSL_TRACE
    if (h->diagnostics & 2) {
        size_t remaining = CgoTLSTraceBudget(h->id);
        if (!remaining) { CgoTLSObserve(h->id, 8, 0, 0, 0, 0, NULL, 0); return; }
        trace_buffer b = {NULL, 0, remaining, 0};
        if (!CRYPTO_THREAD_run_once(&trace_once, trace_init) || !trace_method) {
            CgoTLSObserve(h->id, 8, 0, 0, 0, 0, NULL, 0); return;
        }
        BIO *bio = BIO_new(trace_method);
        if (!bio) { CgoTLSObserve(h->id, 8, 0, 0, 0, 0, NULL, 0); return; }
        BIO_set_data(bio, &b);
        /* Decoder/BIO errors must not become TLS protocol errors. */
        int empty_errors = ERR_peek_error() == 0;
        if (empty_errors) ERR_raise(ERR_LIB_USER, 1);
        ERR_set_mark();
        SSL_trace(write, version, type, buf, length, ssl, bio);
        ERR_pop_to_mark();
        if (empty_errors) ERR_get_error();
        BIO_free(bio);
        CgoTLSObserve(h->id, b.failed ? 8 : 6, write, version, type, 0, b.data, b.length);
        OPENSSL_free(b.data);
    }
#endif
}
static void diagnostic_info(const SSL *ssl, int where, int ret) {
    tls_hooks *h = diagnostic_hooks(ssl); if (!h || !(h->diagnostics & 1)) return;
    const char *text = SSL_state_string_long(ssl);
    CgoTLSObserve(h->id, (where & SSL_CB_ALERT) ? 4 : 2, (where & SSL_CB_WRITE) != 0, SSL_version(ssl), where, ret, (void *)text, strlen(text));
}
static void diagnostic_keylog(const SSL *ssl, const char *line) {
    tls_hooks *h = diagnostic_hooks(ssl); if (!h || !(h->diagnostics & 4)) return;
    size_t len = strnlen(line, h->diagnostic_limit + 1);
    CgoTLSObserve(h->id, 7, 0, 0, 0, 0, (void *)line, len);
}
int X_SSL_diagnostics(SSL *ssl, int flags, size_t limit) {
#ifdef OPENSSL_NO_SSL_TRACE
    if (flags & 2) return 0;
#endif
    tls_hooks *h = diagnostic_hooks(ssl); if (!h) return 0;
    h->diagnostics = flags; h->diagnostic_limit = limit;
    if (flags & 3) SSL_set_msg_callback(ssl, diagnostic_message);
    if (flags & 1) SSL_set_info_callback(ssl, diagnostic_info);
    return 1;
}

void X_SSL_CTX_keylog(SSL_CTX *ctx, int enabled) { SSL_CTX_set_keylog_callback(ctx, enabled ? diagnostic_keylog : NULL); }
