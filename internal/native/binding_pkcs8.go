package native

/*
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <stdlib.h>

static int X_PKEY_write_pkcs8(BIO *bio, EVP_PKEY *key, const char *pass,
 int passlen, const char *ciphername, int version, int prf, int iter, int encrypt) {
 PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key);
 if (p8 == NULL) return 0;
 int ok = 0;
 if (!encrypt) {
  ok = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio,p8);
 } else {
  X509_SIG *enc = NULL;
  if (version == 1) {
   enc = PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC,NULL,pass,passlen,NULL,0,iter,p8);
  } else {
   const EVP_CIPHER *cipher = EVP_get_cipherbyname(ciphername);
   if (cipher != NULL) {
    X509_ALGOR *alg = PKCS5_pbe2_set_iv(cipher,iter,NULL,16,NULL,prf);
    if (alg != NULL) {
     enc = PKCS8_set0_pbe(pass,passlen,p8,alg);
     if (enc == NULL) X509_ALGOR_free(alg);
    }
   }
  }
  if (enc != NULL) { ok = PEM_write_bio_PKCS8(bio,enc); X509_SIG_free(enc); }
 }
 PKCS8_PRIV_KEY_INFO_free(p8);
 return ok;
}
static EVP_PKEY *X_PEM_read_rsa_public(BIO *bio) {
 RSA *rsa = PEM_read_bio_RSAPublicKey(bio,NULL,NULL,NULL);
 if (rsa == NULL) return NULL;
 EVP_PKEY *key = EVP_PKEY_new();
 if (key == NULL || EVP_PKEY_assign_RSA(key,rsa) != 1) { RSA_free(rsa); EVP_PKEY_free(key); return NULL; }
 return key;
}
static int X_PEM_write_rsa_public(BIO *bio, EVP_PKEY *key) {
 RSA *rsa = EVP_PKEY_get1_RSA(key); if (rsa == NULL) return 0;
 int ok = PEM_write_bio_RSAPublicKey(bio,rsa); RSA_free(rsa); return ok;
}
*/
import "C"
import "unsafe"

// X_PKEY_write_pkcs8 写出指定加密方案的 PKCS#8 PEM。
//
// X_PKEY_write_pkcs8 writes PKCS#8 PEM using explicit encryption parameters.
func X_PKEY_write_pkcs8(bio, key unsafe.Pointer, pass, cipher, prf string, version, iter int, encrypt bool) bool {
	p := C.CString(pass)
	defer C.free(unsafe.Pointer(p))
	c := C.CString(cipher)
	defer C.free(unsafe.Pointer(c))
	h := C.CString(prf)
	defer C.free(unsafe.Pointer(h))
	e := C.int(0)
	if encrypt {
		e = 1
	}
	return C.X_PKEY_write_pkcs8((*C.BIO)(bio), (*C.EVP_PKEY)(key), p, C.int(len(pass)), c, C.int(version), C.OBJ_txt2nid(h), C.int(iter), e) == 1
}

// X_PEM_read_rsa_public 加载 PKCS#1 公钥，返回拥有的 EVP_PKEY。
//
// X_PEM_read_rsa_public loads a PKCS#1 public key, returning an owned EVP_PKEY.
func X_PEM_read_rsa_public(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_rsa_public((*C.BIO)(bio)))
}

// X_PEM_write_rsa_public 写出 PKCS#1 公钥。
//
// X_PEM_write_rsa_public writes a PKCS#1 public key.
func X_PEM_write_rsa_public(bio, key unsafe.Pointer) bool {
	return C.X_PEM_write_rsa_public((*C.BIO)(bio), (*C.EVP_PKEY)(key)) == 1
}
