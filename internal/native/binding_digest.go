package native

/*
#include <openssl/evp.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// EVP_sm3 返回 SM3 摘要算法描述符（常量指针，不拥有所有权）。
//
// EVP_sm3 returns the SM3 message digest descriptor. The returned pointer
// points to a static singleton; do NOT free it.
func EVP_sm3() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm3())
}

// EVP_md5 返回 MD5 摘要算法描述符。
//
// EVP_md5 returns the MD5 message digest descriptor (static singleton, do not free).
func EVP_md5() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_md5())
}

// EVP_sha1 返回 SHA-1 摘要算法描述符。
//
// EVP_sha1 returns the SHA-1 message digest descriptor (static singleton, do not free).
func EVP_sha1() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sha1())
}

// EVP_sha224 返回 SHA-224 摘要算法描述符。
//
// EVP_sha224 returns the SHA-224 message digest descriptor (static singleton, do not free).
func EVP_sha224() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sha224())
}

// EVP_sha256 返回 SHA-256 摘要算法描述符。
//
// EVP_sha256 returns the SHA-256 message digest descriptor (static singleton, do not free).
func EVP_sha256() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sha256())
}

// EVP_sha384 返回 SHA-384 摘要算法描述符。
//
// EVP_sha384 returns the SHA-384 message digest descriptor (static singleton, do not free).
func EVP_sha384() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sha384())
}

// EVP_sha512 返回 SHA-512 摘要算法描述符。
//
// EVP_sha512 returns the SHA-512 message digest descriptor (static singleton, do not free).
func EVP_sha512() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sha512())
}

// EVP_MD_get_size 返回摘要算法输出长度（字节）。
//
// EVP_MD_get_size returns the output size of md in bytes (e.g. 32 for SHA-256).
func EVP_MD_get_size(md unsafe.Pointer) int {
	return int(C.EVP_MD_get_size((*C.EVP_MD)(md)))
}

// EVP_MD_get_block_size 返回摘要算法分组长度（字节）。
//
// EVP_MD_get_block_size returns the internal block size of md in bytes
// (e.g. 64 for SHA-256, 128 for SHA-512).
func EVP_MD_get_block_size(md unsafe.Pointer) int {
	return int(C.EVP_MD_get_block_size((*C.EVP_MD)(md)))
}

// EVP_MD_CTX_new 分配新的摘要上下文。
//
// EVP_MD_CTX_new allocates and returns a new, empty EVP_MD_CTX. The caller
// owns the returned pointer and must release it with EVP_MD_CTX_free.
func EVP_MD_CTX_new() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_MD_CTX_new())
}

// EVP_MD_CTX_free 释放摘要上下文。
//
// EVP_MD_CTX_free releases ctx. Safe on NULL; the pointer must not be used
// after free.
func EVP_MD_CTX_free(ctx unsafe.Pointer) {
	C.EVP_MD_CTX_free((*C.EVP_MD_CTX)(ctx))
}

// EVP_MD_CTX_copy_ex 复制摘要上下文（用于不改变原状态的 Sum）。
//
// EVP_MD_CTX_copy_ex duplicates src into dst so the caller can finalize one
// copy without consuming the state of the other. dst must already be allocated.
func EVP_MD_CTX_copy_ex(dst, src unsafe.Pointer) bool {
	return C.EVP_MD_CTX_copy_ex((*C.EVP_MD_CTX)(dst), (*C.EVP_MD_CTX)(src)) == 1
}

// EVP_DigestInit_ex 初始化摘要上下文。
// impl 传 nil 表示使用默认实现。
//
// EVP_DigestInit_ex sets up ctx to use md. Pass nil for impl to use the
// default ENGINE implementation.
func EVP_DigestInit_ex(ctx, md, impl unsafe.Pointer) bool {
	return C.EVP_DigestInit_ex((*C.EVP_MD_CTX)(ctx), (*C.EVP_MD)(md),
		(*C.ENGINE)(impl)) == 1
}

// EVP_DigestUpdate 追加数据到摘要上下文。
// 注意：铜锁该函数第二参数为 const void *（cgo 映射为 unsafe.Pointer）。
//
// EVP_DigestUpdate feeds data into the running digest computation. The Tongsuo
// signature uses const void * which cgo maps to unsafe.Pointer; an empty data
// slice is forwarded as NULL,length=0.
func EVP_DigestUpdate(ctx unsafe.Pointer, data []byte) bool {
	if len(data) == 0 {
		return C.EVP_DigestUpdate((*C.EVP_MD_CTX)(ctx), nil, 0) == 1
	}
	return C.EVP_DigestUpdate((*C.EVP_MD_CTX)(ctx),
		unsafe.Pointer(&data[0]), C.size_t(len(data))) == 1
}

// EVP_DigestFinal_ex 完成摘要计算，将结果写入 md，并通过 n 返回实际长度。
//
// EVP_DigestFinal_ex writes the digest into md and stores the actual digest
// length in *n (if non-nil). After Final the context is reset and may be
// reused only after a fresh EVP_DigestInit_ex.
func EVP_DigestFinal_ex(ctx unsafe.Pointer, md []byte, n *int) bool {
	var s C.uint
	var ok bool
	if len(md) == 0 {
		ok = C.EVP_DigestFinal_ex((*C.EVP_MD_CTX)(ctx), nil, &s) == 1
	} else {
		ok = C.EVP_DigestFinal_ex((*C.EVP_MD_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&md[0])), &s) == 1
	}
	if n != nil {
		*n = int(s)
	}
	return ok
}

// X_EVP_Digest 一次性计算摘要（经 shim 包装，规避跨版本差异）。
//
// X_EVP_Digest is a one-shot helper (X_EVP_Digest shim) that computes the
// digest of data in a single call. The output length is written to *n. The
// shim abstracts over differences between OpenSSL major versions.
func X_EVP_Digest(md unsafe.Pointer, data, out []byte, n *int) bool {
	var s C.uint
	var ok bool
	switch {
	case len(data) == 0 && len(out) == 0:
		ok = C.X_EVP_Digest((*C.EVP_MD)(md), nil, 0, nil, &s) == 1
	case len(data) == 0:
		ok = C.X_EVP_Digest((*C.EVP_MD)(md), nil, 0,
			(*C.uchar)(unsafe.Pointer(&out[0])), &s) == 1
	case len(out) == 0:
		ok = C.X_EVP_Digest((*C.EVP_MD)(md),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)), nil, &s) == 1
	default:
		ok = C.X_EVP_Digest((*C.EVP_MD)(md),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
			(*C.uchar)(unsafe.Pointer(&out[0])), &s) == 1
	}
	if n != nil {
		*n = int(s)
	}
	return ok
}
