/* Link only against the repository shim and the user's installed Tongsuo.
 * The disabled-feature build checks shim fallbacks, not a no-CT native build. */
#include "ssl_handshake.h"
#include <stdio.h>
void CgoTLSRelease(uintptr_t id) {}
int CgoTLSSelect(uintptr_t id, SSL *ssl, char *name, int ntls) { return 1; }
int CgoTLSVerify(uintptr_t id, int ok, int code, int depth, X509 *cert) { return ok; }
int CgoTLSALPN(uintptr_t id, unsigned char *wire, unsigned int length) { return -1; }
void CgoTLSObserve(uintptr_t id, int kind, int write, int version, int type, int code, void *ptr, size_t size) {}
size_t CgoTLSTraceBudget(uintptr_t id) { return 1 << 20; }
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 1;
    X_SSL_CTX_callbacks(ctx);
    if (SSL_CTX_get_keylog_callback(ctx)) return 7;
    X_SSL_CTX_keylog(ctx, 1);
    if (!SSL_CTX_get_keylog_callback(ctx)) return 8;
    X_SSL_CTX_keylog(ctx, 0);
    if (SSL_CTX_get_keylog_callback(ctx)) return 9;
    SSL *ssl = SSL_new(ctx);
    if (!ssl || !X_SSL_attach(ssl, 1)) return 2;
    if (!X_SSL_diagnostics(ssl, 0, 1 << 20)) return 3;
#ifdef OPENSSL_NO_SM2
    if (X_SSL_CTX_rfc8998(ctx) || X_SSL_rfc8998(ssl, 1)) return 4;
#else
    if (!X_SSL_CTX_rfc8998(ctx) || !X_SSL_rfc8998(ssl, 1)) return 4;
#endif
#ifdef OPENSSL_NO_CT
    if (X_SSL_capture_sct(ssl)) return 5;
#else
    if (!X_SSL_capture_sct(ssl)) return 5;
#endif
#ifdef OPENSSL_NO_SSL_TRACE
    if (X_SSL_diagnostics(ssl, 2, 1 << 20)) return 6;
#else
    if (!X_SSL_diagnostics(ssl, 2, 1 << 20)) return 6;
#endif
    SSL_free(ssl); SSL_CTX_free(ctx);
    puts("capability fallbacks verified"); return 0;
}
