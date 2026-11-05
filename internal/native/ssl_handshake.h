#ifndef TONGSUO_GO_SSL_HANDSHAKE_H
#define TONGSUO_GO_SSL_HANDSHAKE_H
#include <openssl/ssl.h>
#include <stdint.h>
int X_SSL_write_owned(SSL *ssl, const void *buf, int len);
int X_SSL_attach(SSL *ssl, uintptr_t id);
void X_SSL_CTX_callbacks(SSL_CTX *ctx);
int X_SSL_switch_context(SSL *ssl, SSL_CTX *ctx);
int X_SSL_CTX_parameters(SSL_CTX *ctx, const char *groups, const char *sigalgs,
                        const unsigned char *dh, size_t dhlen, uint64_t options, long modes);
int X_SSL_CTX_add_chain(SSL_CTX *ctx, X509 *cert);
int X_SSL_set_verify_name(SSL *ssl, const char *host, int ip, unsigned int flags, const char *email);
int X_SSL_CTX_add_client_ca(SSL_CTX *ctx, X509 *cert);
int X_SSL_name_check(X509 *cert, const char *name, int kind, unsigned int flags);
int X_SSL_groups(SSL *s, const char *v);
int X_SSL_sigalgs(SSL *s, const char *v);
int X_SSL_group(SSL *s);
int X_SSL_peer_sig(SSL *s, int *nid);
int X_TLS_chain_num(STACK_OF(X509) *sk);
X509 *X_TLS_chain_value(STACK_OF(X509) *sk, int i);
void X_SSL_send_close_notify(SSL *ssl);
#endif
