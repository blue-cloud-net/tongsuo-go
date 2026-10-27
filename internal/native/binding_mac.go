package native

/*
#include "shim.h"
*/
import "C"
import "unsafe"

// MAC 参数掩码：与 shim.h 的 X_MAC_OPT_* 一一对应。
//
// MAC parameter masks mirroring the X_MAC_OPT_* constants in shim.h.
const (
	// MacOptCipher 表示需要设置底层分组算法名（CMAC / GMAC 使用）。
	//
	// MacOptCipher selects the underlying block cipher name (CMAC / GMAC).
	MacOptCipher = C.X_MAC_OPT_CIPHER
	// MacOptIV 表示需要设置初始向量（GMAC / EIA3 使用）。
	//
	// MacOptIV selects the initialization vector (GMAC / EIA3).
	MacOptIV = C.X_MAC_OPT_IV
	// MacOptCustom 表示需要设置 customization 串（KMAC 使用）。
	//
	// MacOptCustom selects the customization string (KMAC).
	MacOptCustom = C.X_MAC_OPT_CUSTOM
	// MacOptSize 表示需要设置输出长度（KMAC / SipHash 使用）。
	//
	// MacOptSize selects the output size in bytes (KMAC / SipHash).
	MacOptSize = C.X_MAC_OPT_SIZE
	// MacOptDigest 表示需要设置底层摘要算法名（HMAC 使用）。
	//
	// MacOptDigest selects the underlying message-digest name (HMAC).
	MacOptDigest = C.X_MAC_OPT_DIGEST
)

// EVP_MAC_Fetch 按算法名取 MAC 实现（如 "CMAC"、"GMAC"、"KMAC-128"、
// "SIPHASH"、"POLY1305"、"EIA3"、"HMAC"）。
// 取不到时返回 nil（错误已入队列）。
//
// EVP_MAC_Fetch fetches a MAC implementation by name (for example "CMAC",
// "GMAC", "KMAC-128", "SIPHASH", "POLY1305", "EIA3" or "HMAC"). It returns
// nil when the algorithm is unavailable (the error is queued).
func EVP_MAC_Fetch(name string) unsafe.Pointer {
	cname, free := cstr(name)
	defer free()
	return unsafe.Pointer(C.EVP_MAC_fetch(nil, cname, nil))
}

// EVP_MAC_Free 释放 MAC 实现。
//
// EVP_MAC_Free releases a MAC implementation.
func EVP_MAC_Free(mac unsafe.Pointer) {
	if mac == nil {
		return
	}
	C.EVP_MAC_free((*C.EVP_MAC)(mac))
}

// EVP_MAC_CTX_New 创建 MAC 上下文（调用方负责释放）。
//
// EVP_MAC_CTX_New allocates a MAC context (the caller must free it).
func EVP_MAC_CTX_New(mac unsafe.Pointer) unsafe.Pointer {
	if mac == nil {
		return nil
	}
	return unsafe.Pointer(C.EVP_MAC_CTX_new((*C.EVP_MAC)(mac)))
}

// EVP_MAC_CTX_Free 释放 MAC 上下文。
//
// EVP_MAC_CTX_Free releases a MAC context.
func EVP_MAC_CTX_Free(ctx unsafe.Pointer) {
	if ctx == nil {
		return
	}
	C.EVP_MAC_CTX_free((*C.EVP_MAC_CTX)(ctx))
}

// EVP_MAC_CTX_Dup 复制 MAC 上下文（含已设置的参数与已累积的数据）。
// 复制失败时返回 nil（错误已入队列）。
//
// EVP_MAC_CTX_Dup duplicates a MAC context, including the parameters already
// set and the data accumulated so far. It returns nil on failure (the error
// is queued).
func EVP_MAC_CTX_Dup(ctx unsafe.Pointer) unsafe.Pointer {
	if ctx == nil {
		return nil
	}
	return unsafe.Pointer(C.EVP_MAC_CTX_dup((*C.EVP_MAC_CTX)(ctx)))
}

// EVP_MAC_CTX_SetParams 按掩码设置 MAC 上下文参数。
// mask 取 MacOpt* 常量的按位或；未置位的参数不会被设置。
// 成功返回 true，失败返回 false（错误已入队列）。
//
// EVP_MAC_CTX_SetParams sets MAC context parameters selected by mask, which
// is a bitwise OR of the MacOpt* constants. It returns true on success and
// false on failure (the error is queued).
func EVP_MAC_CTX_SetParams(ctx unsafe.Pointer, mask int, cipher, digest string, iv, custom []byte, size int) bool {
	if ctx == nil {
		return false
	}
	ccipher, freeCipher := cstr(cipher)
	defer freeCipher()
	cdigest, freeDigest := cstr(digest)
	defer freeDigest()
	return C.X_EVP_MAC_CTX_set_params((*C.EVP_MAC_CTX)(ctx), C.int(mask),
		ccipher, cdigest,
		bytesPtr(iv), C.size_t(len(iv)),
		bytesPtr(custom), C.size_t(len(custom)),
		C.size_t(size)) == 1
}

// EVP_MAC_Init 用密钥初始化 MAC 上下文。
// key 为空时按 provider 默认处理（如 GMAC 已在 set_params 阶段设过密钥）。
//
// EVP_MAC_Init initialises the MAC context with key. A nil key leaves the
// key to the provider (e.g. GMAC, whose key was already set via
// EVP_MAC_CTX_SetParams).
func EVP_MAC_Init(ctx unsafe.Pointer, key []byte) bool {
	if ctx == nil {
		return false
	}
	return C.EVP_MAC_init((*C.EVP_MAC_CTX)(ctx),
		bytesPtr(key), C.size_t(len(key)), nil) == 1
}

// EVP_MAC_Update 追加一段待认证数据。
//
// EVP_MAC_Update feeds one chunk of data into the MAC context.
func EVP_MAC_Update(ctx unsafe.Pointer, data []byte) bool {
	if ctx == nil {
		return false
	}
	return C.EVP_MAC_update((*C.EVP_MAC_CTX)(ctx),
		bytesPtr(data), C.size_t(len(data))) == 1
}

// EVP_MAC_Final 计算并写出标签，返回写出的字节数。
// out 长度必须不小于上下文报告的标签长度，否则返回 0。
//
// EVP_MAC_Final computes the tag and writes it to out, returning the number
// of bytes written. out must be at least as large as the tag size reported
// by the context; otherwise it returns 0.
func EVP_MAC_Final(ctx unsafe.Pointer, out []byte) int {
	if ctx == nil || len(out) == 0 {
		return 0
	}
	var outl C.size_t
	if C.EVP_MAC_final((*C.EVP_MAC_CTX)(ctx),
		(*C.uchar)(unsafe.Pointer(&out[0])), &outl, C.size_t(len(out))) != 1 {
		return 0
	}
	return int(outl)
}

// EVP_MAC_CTX_Size 返回上下文的标签长度（字节）。
// 上下文未初始化时返回 0。
//
// EVP_MAC_CTX_Size returns the tag size in bytes of the context, or 0 when
// the context is not initialised.
func EVP_MAC_CTX_Size(ctx unsafe.Pointer) int {
	if ctx == nil {
		return 0
	}
	return int(C.EVP_MAC_CTX_get_mac_size((*C.EVP_MAC_CTX)(ctx)))
}

// EVP_MAC_CTX_BlockSize 返回上下文的内部分组长度（字节）。
// provider 未报告分组长度时返回 0。
//
// EVP_MAC_CTX_BlockSize returns the internal block size in bytes of the
// context, or 0 when the provider does not report one.
func EVP_MAC_CTX_BlockSize(ctx unsafe.Pointer) int {
	if ctx == nil {
		return 0
	}
	return int(C.EVP_MAC_CTX_get_block_size((*C.EVP_MAC_CTX)(ctx)))
}
