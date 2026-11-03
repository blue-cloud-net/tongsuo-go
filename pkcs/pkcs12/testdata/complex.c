/* Offline test fixture generator/inspector. All cryptography uses Tongsuo. */
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(void) { ERR_print_errors_fp(stderr); exit(1); }
static void fingerprint(const unsigned char *data, int len) {
 unsigned char digest[32]; unsigned int n; int i;
 if (len < 0 || !EVP_Digest(data,(size_t)len,digest,&n,EVP_sha256(),NULL)) die();
 for(i=0;i<(int)n;i++) printf("%02x",digest[i]);
}
static int attribute_order(const X509_ATTRIBUTE *const *a, const X509_ATTRIBUTE *const *b) {
 return OBJ_cmp(X509_ATTRIBUTE_get0_object((X509_ATTRIBUTE *)*a),X509_ATTRIBUTE_get0_object((X509_ATTRIBUTE *)*b));
}
static void attributes(const PKCS12_SAFEBAG *bag) {
 const STACK_OF(X509_ATTRIBUTE) *attrs=PKCS12_SAFEBAG_get0_attrs(bag);
 int i,n;unsigned char *der=NULL;
 STACK_OF(X509_ATTRIBUTE) *sorted=attrs==NULL?NULL:sk_X509_ATTRIBUTE_dup(attrs);
 if(attrs!=NULL&&sorted==NULL)die();
 if(sorted!=NULL){sk_X509_ATTRIBUTE_set_cmp_func(sorted,attribute_order);sk_X509_ATTRIBUTE_sort(sorted);}
 attrs=sorted;
 printf(" attrs=%d",sk_X509_ATTRIBUTE_num(attrs));
 for(i=0;i<sk_X509_ATTRIBUTE_num(attrs);i++){
  if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(sk_X509_ATTRIBUTE_value(attrs,i)))==NID_friendlyName) {
   ASN1_TYPE *value=X509_ATTRIBUTE_get0_type(sk_X509_ATTRIBUTE_value(attrs,i),0);
   unsigned char *utf8=NULL;int size;
   if(value==NULL||value->type!=V_ASN1_BMPSTRING)die();
   size=ASN1_STRING_to_UTF8(&utf8,value->value.bmpstring);if(size<0)die();
   printf(" name=");fwrite(utf8,1,(size_t)size,stdout);OPENSSL_free(utf8);continue;
  }
  n=i2d_X509_ATTRIBUTE(sk_X509_ATTRIBUTE_value(attrs,i),&der);
  putchar(' ');fingerprint(der,n);OPENSSL_free(der);der=NULL;
 }
 sk_X509_ATTRIBUTE_free(sorted);
}
static void snapshot_bags(const STACK_OF(PKCS12_SAFEBAG) *bags,const char *pass,int depth){
 int i,n,nid;unsigned char *der;PKCS8_PRIV_KEY_INFO *key;
 if(depth>128)die();
 for(i=0;i<sk_PKCS12_SAFEBAG_num(bags);i++){
  const PKCS12_SAFEBAG *bag=sk_PKCS12_SAFEBAG_value(bags,i);
  nid=PKCS12_SAFEBAG_get_nid(bag);der=NULL;
  printf("depth=%d bag=%d type=%s",depth,i,OBJ_nid2sn(nid));attributes(bag);
  if(nid==NID_safeContentsBag){putchar('\n');snapshot_bags(PKCS12_SAFEBAG_get0_safes(bag),pass,depth+1);continue;}
  if(nid==NID_pkcs8ShroudedKeyBag){key=PKCS12_decrypt_skey(bag,pass,-1);if(key==NULL)die();n=i2d_PKCS8_PRIV_KEY_INFO(key,&der);PKCS8_PRIV_KEY_INFO_free(key);}
  else if(nid==NID_certBag){X509 *cert=PKCS12_SAFEBAG_get1_cert(bag);if(cert==NULL)die();n=i2d_X509(cert,&der);X509_free(cert);}
  else if(nid==NID_crlBag){X509_CRL *crl=PKCS12_SAFEBAG_get1_crl(bag);if(crl==NULL)die();n=i2d_X509_CRL(crl,&der);X509_CRL_free(crl);}
  else if(nid==NID_keyBag){n=i2d_PKCS8_PRIV_KEY_INFO(PKCS12_SAFEBAG_get0_p8inf(bag),&der);}
  else {n=i2d_PKCS12_SAFEBAG(bag,&der);}
  printf(" content=");fingerprint(der,n);putchar('\n');OPENSSL_clear_free(der,n>0?(size_t)n:0);
 }
}
static void snapshot(PKCS12 *p12,const char *pass){
 STACK_OF(PKCS7) *safes;STACK_OF(PKCS12_SAFEBAG) *bags;int i;
 if(!PKCS12_verify_mac(p12,pass,-1))die();
 safes=PKCS12_unpack_authsafes(p12);if(safes==NULL)die();
 for(i=0;i<sk_PKCS7_num(safes);i++){
  PKCS7 *safe=sk_PKCS7_value(safes,i);
  printf("safe=%d encrypted=%d\n",i,PKCS7_type_is_encrypted(safe));
  bags=PKCS7_type_is_data(safe)?PKCS12_unpack_p7data(safe):PKCS12_unpack_p7encdata(safe,pass,-1);
  if(bags==NULL)die();
  snapshot_bags(bags,pass,0);
  sk_PKCS12_SAFEBAG_pop_free(bags,PKCS12_SAFEBAG_free);
 }
 sk_PKCS7_pop_free(safes,PKCS7_free);
}
static void attribute(PKCS12_SAFEBAG *bag,int id){
 unsigned char value=(unsigned char)id;
 if(!PKCS12_add_localkeyid(bag,&value,1)||!PKCS12_add_friendlyname_utf8(bag,id==1?"first key":"second key",-1)
    ||!PKCS12_add1_attr_by_txt(bag,"1.2.3.4.77",V_ASN1_UTF8STRING,(const unsigned char *)"custom attribute",16))die();
}
static PKCS12_SAFEBAG *nested(STACK_OF(PKCS12_SAFEBAG) *bags){
 int inner=ASN1_item_i2d((ASN1_VALUE *)bags,NULL,ASN1_ITEM_rptr(PKCS12_SAFEBAGS)),oid=i2d_ASN1_OBJECT(OBJ_nid2obj(NID_safeContentsBag),NULL);
 int explicit_len=ASN1_object_size(1,inner,0),len=ASN1_object_size(1,oid+explicit_len,V_ASN1_SEQUENCE);
 unsigned char *der=OPENSSL_malloc((size_t)len),*p=der;const unsigned char *read;PKCS12_SAFEBAG *bag;
 if(der==NULL)die();
 ASN1_put_object(&p,1,oid+explicit_len,V_ASN1_SEQUENCE,V_ASN1_UNIVERSAL);
 i2d_ASN1_OBJECT(OBJ_nid2obj(NID_safeContentsBag),&p);
 ASN1_put_object(&p,1,inner,0,V_ASN1_CONTEXT_SPECIFIC);ASN1_item_i2d((ASN1_VALUE *)bags,&p,ASN1_ITEM_rptr(PKCS12_SAFEBAGS));
 read=der;bag=d2i_PKCS12_SAFEBAG(NULL,&read,len);OPENSSL_free(der);if(bag==NULL)die();return bag;
}
static PKCS12 *create(const char *pass,int single){
 STACK_OF(PKCS12_SAFEBAG) *inner=NULL,*outer=NULL,*certs=NULL;
 STACK_OF(PKCS7) *safes=sk_PKCS7_new_null();EVP_PKEY *keys[2]={NULL,NULL};X509 *cert;PKCS12 *p12;PKCS12_SAFEBAG *bag;
 int i;unsigned char secret[]={1,7,9};X509_CRL *crl=NULL;ASN1_TIME *at=NULL;
 if(safes==NULL)die();
 for(i=0;i<(single?1:2);i++){
  keys[i]=EVP_PKEY_Q_keygen(NULL,NULL,"RSA",2048);if(keys[i]==NULL)die();
  bag=PKCS12_add_key(&inner,keys[i],0,2345,i?NID_aes_256_cbc:NID_aes_128_cbc,pass);if(bag==NULL)die();attribute(bag,i+1);
  cert=X509_new();if(cert==NULL)die();
  X509_set_version(cert,2);ASN1_INTEGER_set(X509_get_serialNumber(cert),i+1);X509_gmtime_adj(X509_getm_notBefore(cert),-60);X509_gmtime_adj(X509_getm_notAfter(cert),3600);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(cert),"CN",MBSTRING_ASC,(unsigned char *)(i?"second":"first"),-1,-1,0);
  X509_set_issuer_name(cert,X509_get_subject_name(cert));X509_set_pubkey(cert,keys[i]);if(!X509_sign(cert,keys[i],EVP_sha256()))die();
  bag=PKCS12_add_cert(&certs,cert);if(bag==NULL)die();attribute(bag,i+1);
  if(i==0){crl=X509_CRL_new();at=ASN1_TIME_new();if(crl==NULL||at==NULL)die();X509_CRL_set_version(crl,1);X509_CRL_set_issuer_name(crl,X509_get_subject_name(cert));ASN1_TIME_set(at,time(NULL)-60);X509_CRL_set1_lastUpdate(crl,at);ASN1_TIME_set(at,time(NULL)+3600);X509_CRL_set1_nextUpdate(crl,at);if(!X509_CRL_sign(crl,keys[0],EVP_sha256()))die();}
  X509_free(cert);
 }
 if(!single){
  static const unsigned char opaque_der[]={0x30,0x0c,0x06,0x03,0x2a,0x03,0x63,0xa0,0x05,0x04,0x03,0x01,0x02,0x03};
  const unsigned char *opaque_read=opaque_der;
  PKCS12_SAFEBAG *opaque=d2i_PKCS12_SAFEBAG(NULL,&opaque_read,sizeof(opaque_der));
  PKCS8_PRIV_KEY_INFO *plain=EVP_PKEY2PKCS8(keys[0]);
  PKCS12_SAFEBAG *plainbag=plain==NULL?NULL:PKCS12_SAFEBAG_create0_p8inf(plain);
  if(opaque==NULL||plainbag==NULL||sk_PKCS12_SAFEBAG_push(inner,opaque)<=0||sk_PKCS12_SAFEBAG_push(inner,plainbag)<=0)die();
  attribute(plainbag,3);
  if(PKCS12_add_secret(&inner,NID_aes_128_cbc,secret,sizeof(secret))==NULL)die();
  bag=PKCS12_SAFEBAG_create_crl(crl);if(bag==NULL||sk_PKCS12_SAFEBAG_push(certs,bag)<=0)die();
  bag=nested(inner);attribute(bag,7);outer=sk_PKCS12_SAFEBAG_new_null();if(outer==NULL||sk_PKCS12_SAFEBAG_push(outer,bag)<=0)die();
  bag=nested(outer);attribute(bag,8);sk_PKCS12_SAFEBAG_pop_free(outer,PKCS12_SAFEBAG_free);
  outer=sk_PKCS12_SAFEBAG_new_null();if(outer==NULL||sk_PKCS12_SAFEBAG_push(outer,bag)<=0)die();
 }else{outer=inner;inner=NULL;}
 if(!PKCS12_add_safe(&safes,outer,-1,0,NULL)||!PKCS12_add_safe(&safes,certs,NID_pbe_WithSHA1And3_Key_TripleDES_CBC,3456,pass))die();
 p12=PKCS12_add_safes(safes,NID_pkcs7_data);if(p12==NULL||!PKCS12_set_mac(p12,pass,-1,NULL,16,4567,EVP_sha256()))die();
 EVP_PKEY_free(keys[0]);EVP_PKEY_free(keys[1]);X509_CRL_free(crl);ASN1_TIME_free(at);
 sk_PKCS12_SAFEBAG_pop_free(inner,PKCS12_SAFEBAG_free);sk_PKCS12_SAFEBAG_pop_free(outer,PKCS12_SAFEBAG_free);sk_PKCS12_SAFEBAG_pop_free(certs,PKCS12_SAFEBAG_free);sk_PKCS7_pop_free(safes,PKCS7_free);
 return p12;
}
int main(int argc,char **argv){
 PKCS12 *p12;FILE *file;
 if(argc!=4)return 2;
 if(strcmp(argv[1],"create")==0||strcmp(argv[1],"single")==0){p12=create(argv[3],strcmp(argv[1],"single")==0);file=fopen(argv[2],"wb");if(file==NULL||!i2d_PKCS12_fp(file,p12))die();fclose(file);}
 else{file=fopen(argv[2],"rb");if(file==NULL)die();p12=d2i_PKCS12_fp(file,NULL);fclose(file);if(p12==NULL)die();snapshot(p12,argv[3]);}
 PKCS12_free(p12);return 0;
}
