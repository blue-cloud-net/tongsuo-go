#include "shim.h"
#include <openssl/rand.h>
#include <openssl/pkcs12err.h>
#include <string.h>

enum { X_P12_MAX_NESTING = 128, X_P12_MAX_SALT_BYTES = 1048576 };

/* All encryption and ASN.1 processing stays in Tongsuo. No key/cert Bundle
 * conversion occurs: bag attributes and unknown unencrypted payloads survive. */
static int X_p12_random_octets(ASN1_OCTET_STRING *value) {
 int len = value == NULL ? 0 : ASN1_STRING_length(value);
 unsigned char *bytes;
 int ok;
 if (len <= 0 || len > X_P12_MAX_SALT_BYTES) return 0;
 bytes = OPENSSL_malloc((size_t)len);
 if (bytes == NULL) return 0;
 ok = RAND_bytes(bytes, len) == 1 && ASN1_OCTET_STRING_set(value, bytes, len);
 OPENSSL_clear_free(bytes, (size_t)len);
 return ok;
}

static X509_ALGOR *X_p12_algorithm(const X509_ALGOR *old, const char *pbe, int iter) {
 X509_ALGOR *alg = NULL;
 PBE2PARAM *p2 = NULL;
 PBKDF2PARAM *kdf = NULL;
 PBEPARAM *p1 = NULL;
 int nid = OBJ_obj2nid(old->algorithm), cipher_nid;
 const EVP_CIPHER *cipher;
 /* Validate the original algorithm even when migrating its encoding. */
 if (nid == NID_pbes2) {
  p2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), old->parameter);
  if (p2 == NULL || OBJ_obj2nid(p2->keyfunc->algorithm) != NID_id_pbkdf2) goto err;
  cipher_nid = OBJ_obj2nid(p2->encryption->algorithm);
  if (cipher_nid != NID_aes_128_cbc && cipher_nid != NID_aes_192_cbc && cipher_nid != NID_aes_256_cbc) goto err;
  kdf = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), p2->keyfunc->parameter);
  if (kdf == NULL || kdf->salt == NULL || kdf->salt->type != V_ASN1_OCTET_STRING
      || p2->encryption->parameter == NULL || p2->encryption->parameter->type != V_ASN1_OCTET_STRING) goto err;
 } else if (nid != NID_pbe_WithSHA1And3_Key_TripleDES_CBC) goto err;
 if (pbe != NULL && *pbe != '\0') {
  if (strcmp(pbe, "PBE-SHA1-3DES") == 0)
   alg = PKCS5_pbe_set(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, iter, NULL, 0);
  else {
   cipher = EVP_get_cipherbyname(pbe);
   if (cipher != NULL) alg = PKCS5_pbe2_set(cipher, iter, NULL, 0);
  }
  goto done;
 }
 alg = X509_ALGOR_dup(old);
 if (alg == NULL) goto err;
 if (nid == NID_pbes2) {
  if (!X_p12_random_octets(kdf->salt->value.octet_string)
      || !X_p12_random_octets(p2->encryption->parameter->value.octet_string)
      || ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), kdf, &p2->keyfunc->parameter) == NULL
      || ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBE2PARAM), p2, &alg->parameter) == NULL) goto err;
 } else {
  p1 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), old->parameter);
  if (p1 == NULL || !X_p12_random_octets(p1->salt)
      || ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBEPARAM), p1, &alg->parameter) == NULL) goto err;
 }
 goto done;
err:
 X509_ALGOR_free(alg); alg = NULL;
done:
 PBEPARAM_free(p1); PBKDF2PARAM_free(kdf); PBE2PARAM_free(p2);
 return alg;
}

static int X_p12_count(const STACK_OF(PKCS12_SAFEBAG) *bags, int depth, int *keys, const ASN1_TYPE **id) {
 int i, nid;
 if (depth > X_P12_MAX_NESTING) return 0;
 for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
  const PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
  nid = PKCS12_SAFEBAG_get_nid(bag);
  if (nid == NID_keyBag || nid == NID_pkcs8ShroudedKeyBag) {
   if (*keys == INT_MAX) return 0;
   ++*keys; *id = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID);
  } else if (nid == NID_safeContentsBag
      && !X_p12_count(PKCS12_SAFEBAG_get0_safes(bag), depth + 1, keys, id)) return 0;
 }
 return 1;
}

static int X_p12_rename(PKCS12_SAFEBAG *bag, const char *name) {
 STACK_OF(X509_ATTRIBUTE) *attrs = (STACK_OF(X509_ATTRIBUTE) *)PKCS12_SAFEBAG_get0_attrs(bag);
 int i;
 X509_ATTRIBUTE *old, *replacement;
 ASN1_STRING *bmp = NULL;
 if (attrs != NULL) for (i = 0; i < sk_X509_ATTRIBUTE_num(attrs); i++) {
  old = sk_X509_ATTRIBUTE_value(attrs, i);
  if (OBJ_obj2nid(X509_ATTRIBUTE_get0_object(old)) == NID_friendlyName) {
   if (ASN1_mbstring_copy(&bmp, (const unsigned char *)name, -1, MBSTRING_UTF8, B_ASN1_BMPSTRING) < 0) return 0;
   replacement = X509_ATTRIBUTE_create_by_NID(NULL, NID_friendlyName, V_ASN1_BMPSTRING, ASN1_STRING_get0_data(bmp), ASN1_STRING_length(bmp));
   ASN1_STRING_free(bmp);
   if (replacement == NULL) return 0;
   sk_X509_ATTRIBUTE_set(attrs, i, replacement); X509_ATTRIBUTE_free(old); return 1;
  }
 }
 return PKCS12_add_friendlyname_utf8(bag, name, -1);
}

static int X_p12_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *oldpass, const char *newpass,
                     const char *pbe, int iter, const char *name, const ASN1_TYPE *keyid, int depth) {
 int i, nid, len = 0, outlen = 0, ok;
 unsigned char *plain, *encrypted;
 X509_ALGOR *algorithm, *target_alg;
 ASN1_OCTET_STRING *target_data;
 X509_SIG *p8;
 const ASN1_TYPE *id;
 if (depth > X_P12_MAX_NESTING) return 0;
 for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
  PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, i);
  nid = PKCS12_SAFEBAG_get_nid(bag);
  if (nid == NID_safeContentsBag) {
   if (!X_p12_bags((STACK_OF(PKCS12_SAFEBAG) *)PKCS12_SAFEBAG_get0_safes(bag), oldpass, newpass, pbe, iter, name, keyid, depth + 1)) return 0;
  } else if (nid == NID_pkcs8ShroudedKeyBag) {
   p8 = (X509_SIG *)PKCS12_SAFEBAG_get0_pkcs8(bag);
   if (p8 == NULL) return 0;
   X509_SIG_getm(p8, &target_alg, &target_data);
   algorithm = X_p12_algorithm(target_alg, pbe, iter);
   if (algorithm == NULL) return 0;
   plain = PKCS12_pbe_crypt(target_alg, oldpass, -1, ASN1_STRING_get0_data(target_data), ASN1_STRING_length(target_data), NULL, &len, 0);
   if (plain == NULL) { X509_ALGOR_free(algorithm); return 0; }
   encrypted = PKCS12_pbe_crypt(algorithm, newpass, -1, plain, len, NULL, &outlen, 1);
   OPENSSL_clear_free(plain, (size_t)len);
   ok = encrypted != NULL && X509_ALGOR_copy(target_alg, algorithm)
        && ASN1_OCTET_STRING_set(target_data, encrypted, outlen);
   OPENSSL_clear_free(encrypted, (size_t)outlen); X509_ALGOR_free(algorithm);
   if (!ok) return 0;
  }
  if (name != NULL && *name != '\0' && (nid == NID_keyBag || nid == NID_pkcs8ShroudedKeyBag || nid == NID_certBag)) {
   id = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID);
   if (id != NULL && ASN1_TYPE_cmp(id, keyid) == 0 && !X_p12_rename(bag, name)) return 0;
  }
 }
 return 1;
}

PKCS12 *X_PKCS12_reencrypt(PKCS12 *input, const char *oldpass, const char *newpass,
                         const char *pbe, int iter, const char *name) {
 STACK_OF(PKCS7) *safes = NULL;
 STACK_OF(PKCS12_SAFEBAG) **allbags = NULL;
 PKCS12 *output = NULL;
 PKCS7 *safe;
 const X509_ALGOR *macalg;
 const ASN1_OCTET_STRING *macsalt;
 const ASN1_INTEGER *maciter;
 const ASN1_TYPE *keyid = NULL;
 const EVP_MD *md;
 X509_ALGOR *algorithm = NULL;
 ASN1_OCTET_STRING *encrypted = NULL;
 int i, count = 0, keys = 0, mac_iterations, saltlen;
 int64_t original_iter = 1;
 if (!PKCS12_mac_present(input) || !PKCS12_verify_mac(input, oldpass, -1)) goto err;
 PKCS12_get0_mac(NULL, &macalg, &macsalt, &maciter, input);
 md = EVP_get_digestbyobj(macalg->algorithm);
 if (maciter != NULL && (!ASN1_INTEGER_get_int64(&original_iter, maciter) || original_iter <= 0 || original_iter > INT_MAX)) goto err;
 mac_iterations = pbe != NULL && *pbe != '\0' ? iter : (int)original_iter;
 saltlen = ASN1_STRING_length(macsalt);
 if (md == NULL || saltlen <= 0 || saltlen > X_P12_MAX_SALT_BYTES) goto err;
 safes = PKCS12_unpack_authsafes(input);
 if (safes == NULL) goto err;
 count = sk_PKCS7_num(safes);
 if (count <= 0) goto err;
 allbags = OPENSSL_zalloc(sizeof(*allbags) * (size_t)count);
 if (allbags == NULL) goto err;
 for (i = 0; i < count; i++) {
  safe = sk_PKCS7_value(safes, i);
  if (PKCS7_type_is_data(safe)) allbags[i] = PKCS12_unpack_p7data(safe);
  else if (PKCS7_type_is_encrypted(safe)) allbags[i] = PKCS12_unpack_p7encdata(safe, oldpass, -1);
  else goto err;
  if (allbags[i] == NULL || !X_p12_count(allbags[i], 0, &keys, &keyid)) goto err;
 }
 if (name != NULL && *name != '\0' && (keys != 1 || keyid == NULL)) goto err;
 for (i = 0; i < count; i++) {
  if (!X_p12_bags(allbags[i], oldpass, newpass, pbe, iter, name, keyid, 0)) goto err;
  safe = sk_PKCS7_value(safes, i);
  if (PKCS7_type_is_data(safe)) {
   PKCS7 *packed = PKCS12_pack_p7data(allbags[i]);
   if (packed == NULL) goto err;
   sk_PKCS7_set(safes, i, packed); PKCS7_free(safe);
  } else {
   PKCS7_ENC_CONTENT *enc = safe->d.encrypted->enc_data;
   algorithm = X_p12_algorithm(enc->algorithm, pbe, iter);
   if (algorithm == NULL) goto err;
   encrypted = PKCS12_item_i2d_encrypt(algorithm, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), newpass, -1, allbags[i], 1);
   if (encrypted == NULL) goto err;
   X509_ALGOR_free(enc->algorithm); enc->algorithm = algorithm; algorithm = NULL;
   ASN1_OCTET_STRING_free(enc->enc_data); enc->enc_data = encrypted; encrypted = NULL;
  }
 }
 output = PKCS12_init(NID_pkcs7_data);
 if (output == NULL || !PKCS12_pack_authsafes(output, safes)
     || !PKCS12_set_mac(output, newpass, -1, NULL, saltlen, mac_iterations, md)) {
  PKCS12_free(output); output = NULL;
 }
err:
 X509_ALGOR_free(algorithm); ASN1_OCTET_STRING_free(encrypted);
 if (allbags != NULL) for (i = 0; i < count; i++) sk_PKCS12_SAFEBAG_pop_free(allbags[i], PKCS12_SAFEBAG_free);
 OPENSSL_free(allbags); sk_PKCS7_pop_free(safes, PKCS7_free);
 if (output == NULL) ERR_raise(ERR_LIB_PKCS12, ERR_R_UNSUPPORTED);
 return output;
}
