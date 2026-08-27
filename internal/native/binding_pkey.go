package native

/*
#include <openssl/evp.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// X_EVP_PKEY_Q_keygen_sm2 生成 SM2 密钥对（经 shim 包装可变参函数）。
func X_EVP_PKEY_Q_keygen_sm2() unsafe.Pointer {
	return unsafe.Pointer(C.X_EVP_PKEY_Q_keygen_sm2())
}

// X_PEM_read_bio_PrivateKey 从 BIO 读取 PEM 私钥（PKCS#8）。
func X_PEM_read_bio_PrivateKey(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_PrivateKey((*C.BIO)(bio)))
}

// X_PEM_write_bio_PrivateKey 将私钥以 PEM（PKCS#8）写入 BIO。
func X_PEM_write_bio_PrivateKey(bio unsafe.Pointer, pkey unsafe.Pointer) bool {
	return C.X_PEM_write_bio_PrivateKey((*C.BIO)(bio), (*C.EVP_PKEY)(pkey)) == 1
}

// X_PEM_read_bio_PUBKEY 从 BIO 读取 PEM 公钥（SubjectPublicKeyInfo）。
func X_PEM_read_bio_PUBKEY(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_PUBKEY((*C.BIO)(bio)))
}

// X_PEM_write_bio_PUBKEY 将公钥以 PEM（SubjectPublicKeyInfo）写入 BIO。
func X_PEM_write_bio_PUBKEY(bio unsafe.Pointer, pkey unsafe.Pointer) bool {
	return C.X_PEM_write_bio_PUBKEY((*C.BIO)(bio), (*C.EVP_PKEY)(pkey)) == 1
}

// EVP_PKEY_free 释放密钥对象。
func EVP_PKEY_free(pkey unsafe.Pointer) {
	C.EVP_PKEY_free((*C.EVP_PKEY)(pkey))
}

// EVP_PKEY_CTX_new_from_pkey 基于密钥创建操作上下文。
func EVP_PKEY_CTX_new_from_pkey(pkey unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.EVP_PKEY_CTX_new_from_pkey(nil, (*C.EVP_PKEY)(pkey), nil))
}

// EVP_PKEY_CTX_free 释放操作上下文。
func EVP_PKEY_CTX_free(ctx unsafe.Pointer) {
	C.EVP_PKEY_CTX_free((*C.EVP_PKEY_CTX)(ctx))
}

// EVP_PKEY_encrypt_init 初始化加密上下文。
func EVP_PKEY_encrypt_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_encrypt_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_encrypt 加密数据（SM2 输出为 ASN.1 DER，含 C1C3C2）。
// 注意：*outlen 为容量入/实际出，实际调用时必须把缓冲容量传入。
func EVP_PKEY_encrypt(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	var l C.size_t
	if len(out) > 0 {
		l = C.size_t(len(out)) // 输入容量
	}
	var ok bool
	switch {
	case len(in) == 0 && len(out) == 0:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l, nil, 0) == 1
	case len(in) == 0:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l, nil, 0) == 1
	case len(out) == 0:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	default:
		ok = C.EVP_PKEY_encrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	}
	if outl != nil {
		*outl = int(l)
	}
	return ok
}

// EVP_PKEY_decrypt_init 初始化解密上下文。
func EVP_PKEY_decrypt_init(ctx unsafe.Pointer) bool {
	return C.EVP_PKEY_decrypt_init((*C.EVP_PKEY_CTX)(ctx)) == 1
}

// EVP_PKEY_decrypt 解密数据。*outlen 为容量入/实际出。
func EVP_PKEY_decrypt(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	var l C.size_t
	if len(out) > 0 {
		l = C.size_t(len(out)) // 输入容量
	}
	var ok bool
	switch {
	case len(in) == 0 && len(out) == 0:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l, nil, 0) == 1
	case len(in) == 0:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l, nil, 0) == 1
	case len(out) == 0:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx), nil, &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	default:
		ok = C.EVP_PKEY_decrypt((*C.EVP_PKEY_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.size_t(len(in))) == 1
	}
	if outl != nil {
		*outl = int(l)
	}
	return ok
}

// EVP_DigestSignInit 初始化签名上下文，返回内部 EVP_PKEY_CTX（由 MD_CTX 拥有，勿单独释放）。
func EVP_DigestSignInit(ctx, md, e, pkey unsafe.Pointer) (bool, unsafe.Pointer) {
	var pctx *C.EVP_PKEY_CTX
	ok := C.EVP_DigestSignInit((*C.EVP_MD_CTX)(ctx), &pctx, (*C.EVP_MD)(md),
		(*C.ENGINE)(e), (*C.EVP_PKEY)(pkey)) == 1
	return ok, unsafe.Pointer(pctx)
}

// EVP_DigestVerifyInit 初始化验签上下文，返回内部 EVP_PKEY_CTX（由 MD_CTX 拥有）。
func EVP_DigestVerifyInit(ctx, md, e, pkey unsafe.Pointer) (bool, unsafe.Pointer) {
	var pctx *C.EVP_PKEY_CTX
	ok := C.EVP_DigestVerifyInit((*C.EVP_MD_CTX)(ctx), &pctx, (*C.EVP_MD)(md),
		(*C.ENGINE)(e), (*C.EVP_PKEY)(pkey)) == 1
	return ok, unsafe.Pointer(pctx)
}

// EVP_PKEY_CTX_set1_id 设置 SM2 用户标识（userId）。
func EVP_PKEY_CTX_set1_id(pctx unsafe.Pointer, id []byte) bool {
	if len(id) == 0 {
		return C.EVP_PKEY_CTX_set1_id((*C.EVP_PKEY_CTX)(pctx), nil, 0) == 1
	}
	return C.EVP_PKEY_CTX_set1_id((*C.EVP_PKEY_CTX)(pctx),
		unsafe.Pointer(&id[0]), C.int(len(id))) == 1
}

// EVP_PKEY_size 返回密钥的最大签名/加密输出长度（字节）。
func EVP_PKEY_size(pkey unsafe.Pointer) int {
	return int(C.EVP_PKEY_size((*C.EVP_PKEY)(pkey)))
}

// EVP_DigestSignUpdate 追加数据到签名上下文（const void * → unsafe.Pointer）。
func EVP_DigestSignUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.EVP_DigestSignUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestSignFinal 完成签名，写入 sig，实际长度通过 siglen 返回。
// 注意：*siglen 为容量入/实际出，须传入缓冲容量。
func EVP_DigestSignFinal(ctx unsafe.Pointer, sig []byte, siglen *int) bool {
	var l C.size_t
	if len(sig) > 0 {
		l = C.size_t(len(sig)) // 输入容量
	}
	var ok bool
	if len(sig) == 0 {
		ok = C.EVP_DigestSignFinal((*C.EVP_MD_CTX)(ctx), nil, &l) == 1
	} else {
		ok = C.EVP_DigestSignFinal((*C.EVP_MD_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&sig[0])), &l) == 1
	}
	if siglen != nil {
		*siglen = int(l)
	}
	return ok
}

// EVP_DigestVerifyUpdate 追加数据到验签上下文。
func EVP_DigestVerifyUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.EVP_DigestVerifyUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestVerifyFinal 校验签名。
func EVP_DigestVerifyFinal(ctx unsafe.Pointer, sig []byte) bool {
	if len(sig) == 0 {
		return C.EVP_DigestVerifyFinal((*C.EVP_MD_CTX)(ctx), nil, 0) == 1
	}
	return C.EVP_DigestVerifyFinal((*C.EVP_MD_CTX)(ctx),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) == 1
}
