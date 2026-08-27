package native

/*
#include <openssl/hmac.h>
*/
import "C"
import "unsafe"

// HMAC_CTX_new 分配新的 HMAC 上下文。
func HMAC_CTX_new() unsafe.Pointer {
	return unsafe.Pointer(C.HMAC_CTX_new())
}

// HMAC_CTX_free 释放 HMAC 上下文。
func HMAC_CTX_free(ctx unsafe.Pointer) {
	C.HMAC_CTX_free((*C.HMAC_CTX)(ctx))
}

// HMAC_CTX_copy 复制 HMAC 上下文（用于不改变原状态的 Sum）。
func HMAC_CTX_copy(dst, src unsafe.Pointer) bool {
	return C.HMAC_CTX_copy((*C.HMAC_CTX)(dst), (*C.HMAC_CTX)(src)) == 1
}

// HMAC_Init_ex 初始化 HMAC 上下文（设置密钥与摘要算法）。
// key 为 const void * → unsafe.Pointer。
func HMAC_Init_ex(ctx unsafe.Pointer, key []byte, md unsafe.Pointer) bool {
	if len(key) == 0 {
		return C.HMAC_Init_ex((*C.HMAC_CTX)(ctx), nil, 0, (*C.EVP_MD)(md), nil) == 1
	}
	return C.HMAC_Init_ex((*C.HMAC_CTX)(ctx),
		unsafe.Pointer(&key[0]), C.int(len(key)), (*C.EVP_MD)(md), nil) == 1
}

// HMAC_Update 追加数据到 HMAC 上下文。
func HMAC_Update(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return C.HMAC_Update((*C.HMAC_CTX)(ctx),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) == 1
}

// HMAC_Final 输出 HMAC 结果，实际长度通过 n 返回。
func HMAC_Final(ctx unsafe.Pointer, out []byte, n *int) bool {
	var l C.uint
	var ok bool
	if len(out) == 0 {
		ok = C.HMAC_Final((*C.HMAC_CTX)(ctx), nil, &l) == 1
	} else {
		ok = C.HMAC_Final((*C.HMAC_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l) == 1
	}
	if n != nil {
		*n = int(l)
	}
	return ok
}
