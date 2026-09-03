package native

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// bytesPtr 返回切片的底层指针;空切片返回 nil。
//
// bytesPtr returns a pointer to the slice's backing array, or nil for an
// empty slice.
func bytesPtr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// cstr 分配一个 NUL 结尾的 C 字符串副本,并返回释放函数。
//
// cstr allocates a NUL-terminated C copy of s and returns a release
// function; an empty string yields a nil pointer and a no-op release.
func cstr(s string) (*C.char, func()) {
	if s == "" {
		return nil, func() {}
	}
	c := C.CString(s)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

// EVP_KDF_HKDF 执行一次性 HKDF（RFC 5869）派生。
// mode 取 EVP_KDF_HKDF_MODE_*（0=extract-and-expand）；digest 为摘要算法名
// （如 "SHA256"）。成功返回 true，失败返回 false（错误已入队列）。
//
// EVP_KDF_HKDF performs a one-shot HKDF (RFC 5869) derivation.
// mode is one of EVP_KDF_HKDF_MODE_* (0 = extract-and-expand); digest is the
// message-digest name (for example "SHA256"). It returns true on success and
// false on failure (the error is queued for ERR_get_error).
func EVP_KDF_HKDF(digest string, mode int, key, salt, info, out []byte) bool {
	cd, free := cstr(digest)
	defer free()
	return C.X_EVP_KDF_HKDF(cd, C.int(mode),
		bytesPtr(key), C.size_t(len(key)),
		bytesPtr(salt), C.size_t(len(salt)),
		bytesPtr(info), C.size_t(len(info)),
		bytesPtr(out), C.size_t(len(out))) == 1
}

// EVP_KDF_PBKDF2 执行一次性 PBKDF2（RFC 8018）派生。
// digest 为摘要算法名（如 "SHA1"、"SHA256"）；iter 为迭代次数。成功返回 true。
//
// EVP_KDF_PBKDF2 performs a one-shot PBKDF2 (RFC 8018) derivation.
// digest is the message-digest name (for example "SHA1" or "SHA256"); iter is
// the iteration count. It returns true on success.
func EVP_KDF_PBKDF2(digest string, pass, salt []byte, iter int, out []byte) bool {
	cd, free := cstr(digest)
	defer free()
	return C.X_EVP_KDF_PBKDF2(cd,
		bytesPtr(pass), C.size_t(len(pass)),
		bytesPtr(salt), C.size_t(len(salt)),
		C.int(iter),
		bytesPtr(out), C.size_t(len(out))) == 1
}

// EVP_KDF_Available 探测指定 KDF 算法是否可用（provider 是否加载）。
// 探测失败会清空队列中的错误,不影响后续错误读取。
//
// EVP_KDF_Available reports whether the named KDF algorithm is available
// (its provider is loaded). A failed probe clears the error queue so it does
// not disturb later error reads.
func EVP_KDF_Available(algorithm string) bool {
	ca, free := cstr(algorithm)
	defer free()
	return C.X_EVP_KDF_available(ca) == 1
}
