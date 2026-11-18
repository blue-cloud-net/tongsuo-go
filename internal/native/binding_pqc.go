package native

/*
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdlib.h>

static int X_EVP_PQC_signature_init(EVP_MD_CTX *ctx, EVP_PKEY *key, void *context,
                                    size_t context_len, int encoded, int sign) {
    int message_encoding = !encoded;
    OSSL_PARAM params[3];
    size_t count = 0;
    if (context_len != 0)
        params[count++] = OSSL_PARAM_construct_octet_string("context-string", context, context_len);
    if (encoded)
        params[count++] = OSSL_PARAM_construct_int("message-encoding", &message_encoding);
    params[count] = OSSL_PARAM_construct_end();
    return sign ? EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, params)
                : EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, params);
}
*/
import "C"

import "unsafe"

// EVP_PKEY_get0_type_name 返回原生密钥类型名的 Go 副本。
//
// EVP_PKEY_get0_type_name returns a Go copy of the native key type name.
func EVP_PKEY_get0_type_name(key unsafe.Pointer) string {
	return C.GoString(C.EVP_PKEY_get0_type_name((*C.EVP_PKEY)(key)))
}

// EVP_PKEY_CTX_new_from_name 按名称创建密钥上下文。
//
// EVP_PKEY_CTX_new_from_name creates a key context by algorithm name.
func EVP_PKEY_CTX_new_from_name(name string) unsafe.Pointer {
	alg := C.CString(name)
	defer C.free(unsafe.Pointer(alg))
	return unsafe.Pointer(C.EVP_PKEY_CTX_new_from_name(nil, alg, nil))
}

// EVP_PKEY_keygen 生成密钥并转移所有权。
//
// EVP_PKEY_keygen generates a key and transfers ownership.
func EVP_PKEY_keygen(ctx unsafe.Pointer) unsafe.Pointer {
	pctx := (*C.EVP_PKEY_CTX)(ctx)
	if C.EVP_PKEY_keygen_init(pctx) != 1 {
		return nil
	}
	var key *C.EVP_PKEY
	if C.EVP_PKEY_keygen(pctx, &key) != 1 {
		return nil
	}
	return unsafe.Pointer(key)
}

// EVP_PKEY_encapsulate 封装共享秘密，写入预分配的密文与秘密缓冲区。
//
// EVP_PKEY_encapsulate encapsulates a shared secret into preallocated buffers.
func EVP_PKEY_encapsulate(ctx unsafe.Pointer, ciphertext, secret []byte) bool {
	pctx := (*C.EVP_PKEY_CTX)(ctx)
	ctLen, secretLen := C.size_t(len(ciphertext)), C.size_t(len(secret))
	return C.EVP_PKEY_encapsulate_init(pctx, nil) == 1 &&
		C.EVP_PKEY_encapsulate(pctx, (*C.uchar)(unsafe.Pointer(unsafe.SliceData(ciphertext))), &ctLen,
			(*C.uchar)(unsafe.Pointer(unsafe.SliceData(secret))), &secretLen) == 1 &&
		ctLen == C.size_t(len(ciphertext)) && secretLen == C.size_t(len(secret))
}

// EVP_PKEY_decapsulate 解封装密文，将共享秘密写入预分配的缓冲区。
//
// EVP_PKEY_decapsulate decapsulates a ciphertext into the preallocated secret buffer.
func EVP_PKEY_decapsulate(ctx unsafe.Pointer, ciphertext, secret []byte) bool {
	pctx := (*C.EVP_PKEY_CTX)(ctx)
	secretLen := C.size_t(len(secret))
	return C.EVP_PKEY_decapsulate_init(pctx, nil) == 1 &&
		C.EVP_PKEY_decapsulate(pctx, (*C.uchar)(unsafe.Pointer(unsafe.SliceData(secret))), &secretLen,
			(*C.uchar)(unsafe.Pointer(unsafe.SliceData(ciphertext))), C.size_t(len(ciphertext))) == 1 &&
		secretLen == C.size_t(len(secret))
}

// X_EVP_PQC_signature_init 配置一次性签验以及原生消息编码。
//
// X_EVP_PQC_signature_init configures one-shot signing or verification and message encoding.
func X_EVP_PQC_signature_init(ctx, key unsafe.Pointer, context []byte, encoded, sign bool) bool {
	// Keep the OSSL_PARAM array and its referenced data within one C call.
	return C.X_EVP_PQC_signature_init((*C.EVP_MD_CTX)(ctx), (*C.EVP_PKEY)(key),
		unsafe.Pointer(unsafe.SliceData(context)), C.size_t(len(context)), C.int(boolInt(encoded)), C.int(boolInt(sign))) == 1
}
