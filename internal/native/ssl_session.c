#include "ssl_handshake.h"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <string.h>

/* Session callbacks copy serialized state; no borrowed session escapes. */
extern void CgoTLSNewSession(uintptr_t, SSL_SESSION *);
extern SSL_SESSION *CgoTLSGetSession(uintptr_t, unsigned char *, int);
extern int CgoTLSTicketKey(uintptr_t, unsigned char *, unsigned char *, int);
static int session_ticket_generate(SSL *ssl, void *unused) {
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    int count = chain ? sk_X509_num(chain) : 0;
    size_t length = 0;
    for (int i = 0; i < count; i++) {
        int n = i2d_X509(sk_X509_value(chain, i), NULL);
        if (n <= 0 || length + (size_t)n > 1048576) return 0;
        length += n;
    }
    if (!length) return 1;
    unsigned char *data = OPENSSL_malloc(length), *cursor = data;
    if (!data) return 0;
    for (int i = 0; i < count; i++) i2d_X509(sk_X509_value(chain, i), &cursor);
    int ok = SSL_SESSION_set1_ticket_appdata(SSL_get_session(ssl), data, length);
    OPENSSL_free(data);
    return ok;
}
static int session_new_cb(SSL *ssl, SSL_SESSION *session) {
    if (SSL_is_server(ssl) && !session_ticket_generate(ssl, NULL)) return 0;
    uintptr_t id = X_SSL_hooks_id(ssl);
    if (id) CgoTLSNewSession(id, session);
    return 0;
}
static SSL_SESSION *session_get_cb(SSL *ssl, const unsigned char *key, int len, int *copy) {
    uintptr_t id = X_SSL_hooks_id(ssl);
    *copy = 0; /* Go thunk returns a newly decoded, owned session. */
    return id ? CgoTLSGetSession(id, (unsigned char *)key, len) : NULL;
}
static int ticket_key_cb(SSL *ssl, unsigned char name[16], unsigned char *iv,
                         EVP_CIPHER_CTX *cipher, HMAC_CTX *mac, int enc) {
    unsigned char key[64];
    uintptr_t id = X_SSL_hooks_id(ssl);
    int status = id ? CgoTLSTicketKey(id, name, key, enc) : -1;
    if (status <= 0) return status;
    int ok;
    if (enc) {
        memcpy(name, key, 16);
        ok = RAND_bytes(iv, 16) == 1 && EVP_EncryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key+16, iv) == 1;
    } else {
        ok = EVP_DecryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key+16, iv) == 1;
    }
    ok = ok && HMAC_Init_ex(mac, key+32, 32, EVP_sha256(), NULL) == 1;
    OPENSSL_cleanse(key, sizeof(key));
    return ok ? status : -1;
}
int X_SSL_CTX_sessions(SSL_CTX *ctx, int server, int disabled, int tickets, const unsigned char *domain) {
    SSL_CTX_sess_set_new_cb(ctx, session_new_cb);
    SSL_CTX_sess_set_get_cb(ctx, session_get_cb);
    SSL_CTX_set_session_cache_mode(ctx, (server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT) |
        SSL_SESS_CACHE_NO_INTERNAL_STORE | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
    if (disabled) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
        if (server && !SSL_CTX_set_num_tickets(ctx, 0)) return 0;
    } else if (server && tickets >= 0 && !SSL_CTX_set_num_tickets(ctx, tickets)) return 0;
    if (server) {
        if (!SSL_CTX_set_session_id_context(ctx, domain, 32)) return 0;
        if (!SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_key_cb)) return 0;
        if (!SSL_CTX_set_session_ticket_cb(ctx, session_ticket_generate, NULL, NULL)) return 0;
    }
    return 1;
}
extern void CgoTLSReverified(uintptr_t, STACK_OF(X509) *);
extern void CgoTLSResumedPeers(uintptr_t, X509 *, STACK_OF(X509) *);
/* Re-run current verification for each authenticated leaf. NTLS needs both leaves. */
static int session_verify_leaf(SSL *ssl, X509 *peer, STACK_OF(X509) *chain) {
    X509_STORE_CTX *store = X509_STORE_CTX_new();
    if (!store) return 0;
    int ok = X509_STORE_CTX_init(store, SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl)), peer, chain);
    if (ok) {
        ok = X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(store), SSL_get0_param(ssl));
        if (ok) ok = X509_STORE_CTX_set_default(store, SSL_is_server(ssl) ? "ssl_client" : "ssl_server");
        X509_STORE_CTX_set_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx(), ssl);
        X509_STORE_CTX_set_verify_cb(store, SSL_get_verify_callback(ssl));
        if (ok) ok = X509_verify_cert(store);
        SSL_set_verify_result(ssl, X509_STORE_CTX_get_error(store));
        if (ok && X509_STORE_CTX_get_error(store) == X509_V_OK) {
            uintptr_t id = X_SSL_hooks_id(ssl);
            if (id) CgoTLSReverified(id, X509_STORE_CTX_get0_chain(store));
        }
    }
    X509_STORE_CTX_free(store);
    return ok;
}
static int session_chain_append(STACK_OF(X509) *chain, const unsigned char *data, size_t len) {
    if (!len) return 1;
    if (len > 1048576) return 0;
    const unsigned char *end = data + len;
    while (data < end) {
        X509 *cert = d2i_X509(NULL, &data, end - data);
        if (!cert || !sk_X509_push(chain, cert)) { X509_free(cert); return 0; }
    }
    return 1;
}
int X_SSL_reverify(SSL *ssl, const unsigned char *extra, size_t extra_len) {
    X509 *peer = SSL_get1_peer_certificate(ssl);
    if (!peer) return 0;
    STACK_OF(X509) *chain = sk_X509_new_null();
    int ok = chain && session_chain_append(chain, extra, extra_len);
    if (ok && SSL_is_server(ssl)) {
        void *app = NULL;
        size_t app_len = 0;
        if (SSL_SESSION_get0_ticket_appdata(SSL_get_session(ssl), &app, &app_len))
            ok = session_chain_append(chain, app, app_len);
    }
    if (ok) {
        uintptr_t id = X_SSL_hooks_id(ssl);
        if (id) CgoTLSResumedPeers(id, peer, chain);
        ok = session_verify_leaf(ssl, peer, chain);
    }
    if (ok && SSL_version(ssl) == NTLS1_1_VERSION) {
        X509 *enc = NULL;
        for (int i = 0; i < sk_X509_num(chain); i++) {
            X509 *candidate = sk_X509_value(chain, i);
            uint32_t usage = X509_get_key_usage(candidate);
            if (X509_cmp(candidate, peer) != 0 && usage != UINT32_MAX &&
                (usage & (KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT | KU_KEY_AGREEMENT))) {
                enc = candidate;
                break;
            }
        }
        if (!enc) {
            SSL_set_verify_result(ssl, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT);
            ok = 0;
        } else {
            ok = session_verify_leaf(ssl, enc, chain);
        }
    }
    sk_X509_pop_free(chain, X509_free);
    X509_free(peer);
    return ok;
}
