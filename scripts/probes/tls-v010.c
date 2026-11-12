#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ct.h>
#include <stdio.h>
static int messages, infos, keys;
static void msg(int w,int v,int t,const void *b,size_t n,SSL *s,void *a){messages++;}
static void info(const SSL *s,int w,int r){infos++;}
static void key(const SSL *s,const char *line){keys++;}
static int ct(const CT_POLICY_EVAL_CTX *c,const STACK_OF(SCT) *s,void *a){return 1;}
int main(int argc,char **argv){
 const char *suite=argc>1?argv[1]:"TLS_SM4_GCM_SM3";
 EVP_PKEY *p=EVP_PKEY_Q_keygen(NULL,NULL,"SM2"); X509 *x=X509_new();
 if(!p||!x) return 2;
 X509_set_version(x,2); ASN1_INTEGER_set(X509_get_serialNumber(x),1);
 X509_gmtime_adj(X509_getm_notBefore(x),-60); X509_gmtime_adj(X509_getm_notAfter(x),3600);
 X509_set_pubkey(x,p); X509_NAME *n=X509_get_subject_name(x);
 X509_NAME_add_entry_by_txt(n,"CN",MBSTRING_ASC,(unsigned char*)"localhost",-1,-1,0);
 X509_set_issuer_name(x,n); if(!X509_sign(x,p,EVP_sm3())) return 3;
 SSL_CTX *a=SSL_CTX_new(TLS_client_method()),*b=SSL_CTX_new(TLS_server_method());
 SSL_CTX *ctxs[]={a,b};
 for(int i=0;i<2;i++){
 SSL_CTX *c=ctxs[i]; SSL_CTX_enable_sm_tls13_strict(c);
 if(!SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)||!SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)||!SSL_CTX_set_ciphersuites(c,suite)||!SSL_CTX_set1_groups_list(c,"curveSM2")||!SSL_CTX_set1_sigalgs_list(c,"sm2sig_sm3")) return 4;
 SSL_CTX_set_msg_callback(c,msg); SSL_CTX_set_info_callback(c,info); SSL_CTX_set_keylog_callback(c,key);
 }
 if(!SSL_CTX_use_certificate(b,x)||!SSL_CTX_use_PrivateKey(b,p)||!SSL_CTX_set_ct_validation_callback(a,ct,NULL))return 5;
 SSL *client=SSL_new(a),*server=SSL_new(b); BIO *l,*r;
 BIO_new_bio_pair(&l,0,&r,0); SSL_set_bio(client,l,l); SSL_set_bio(server,r,r);
 SSL_set_connect_state(client); SSL_set_accept_state(server);
 int ok=0;
 for(int i=0;i<100;i++){
 int z=SSL_do_handshake(client);if(z!=1){int e=SSL_get_error(client,z);if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE)break;}
 z=SSL_do_handshake(server);if(z!=1){int e=SSL_get_error(server,z);if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE)break;}
 if(SSL_is_init_finished(client)&&SSL_is_init_finished(server)){ok=1;break;}
 }
 const STACK_OF(SCT) *scts=SSL_get0_peer_scts(client);
 printf("suite=%s success=%d version=%s cipher=%s group=%ld messages=%d states=%d keylog_lines=%d scts=%d secure_renegotiation=%ld\n",suite,ok,SSL_get_version(client),SSL_get_cipher_name(client),SSL_get_negotiated_group(client),messages,infos,keys,scts?sk_SCT_num(scts):0,SSL_get_secure_renegotiation_support(client));
 if(!ok)ERR_print_errors_fp(stderr);
 SSL_free(client);SSL_free(server);SSL_CTX_free(a);SSL_CTX_free(b);X509_free(x);EVP_PKEY_free(p);return ok?0:1;
}
