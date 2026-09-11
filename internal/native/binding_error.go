package native

/*
#include <openssl/err.h>
#include <stdlib.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// PopError 从错误队列取出并返回一个错误码；队列为空返回 0。
// PopError wraps ERR_get_error; it pops the earliest error code from the
// current thread's OpenSSL error queue. Returns 0 when the queue is empty.
func PopError() uint64 {
	return uint64(C.ERR_get_error())
}

// ErrorString 返回错误码对应的错误描述字符串。
// 使用 ERR_error_string_n（线程安全，写入本地缓冲区）。
// ErrorString wraps the thread-safe ERR_error_string_n; the description is
// written into a 256-byte stack buffer, so codes producing longer text are
// truncated. Pass an error code from PopError.
func ErrorString(code uint64) string {
	var buf [256]C.char
	C.ERR_error_string_n(C.ulong(code), &buf[0], C.size_t(len(buf)))
	return C.GoString(&buf[0])
}

// Cleanse 安全清零 len(b) 字节的内存。
//
// 内部封装 OPENSSL_cleanse（volatilized 函数指针），用于承载密钥材料或
// 口令的缓冲在用毕后立即覆写，避免编译器在 release 构建里把"未再引用"
// 的 memcpy/memset 消除掉。nil 或 len==0 时为 no-op。
//
// Cleanse securely zeroes len(b) bytes of memory by dispatching through
// OPENSSL_cleanse (whose volatile function pointer prevents the compiler
// from optimising the memset away). Use it to wipe buffers that held key
// material or passphrases. nil or len==0 is a no-op.
func Cleanse(b []byte) {
	if len(b) == 0 {
		return
	}
	C.X_OPENSSL_cleanse(unsafe.Pointer(&b[0]), C.size_t(len(b)))
}

// ErrGetLib 从错误码中取出 library 部分（openssl/err.h 的 ERR_GET_LIB 宏）。
//
// ErrGetLib extracts the library portion of an OpenSSL error code (mirrors
// the ERR_GET_LIB macro, which is a macro and cannot cross cgo directly).
func ErrGetLib(code uint64) int {
	return int(C.X_ERR_get_lib(C.ulong(code)))
}

// ErrGetReason 从错误码中取出 reason 部分（openssl/err.h 的 ERR_GET_REASON）。
//
// ErrGetReason extracts the reason portion of an OpenSSL error code
// (mirrors the ERR_GET_REASON macro).
func ErrGetReason(code uint64) int {
	return int(C.X_ERR_get_reason(C.ulong(code)))
}

/*
 * ERR_LIB_* 与 ERR_R_*（本项目实际使用的子集）。
 *
 * OpenSSL/Tongsuo 错误码 = (lib<<24) | (reason & 0xfff)，但 lib 与 reason
 * 并不总在 <<24 范围，所以本层仅暴露数值常量；调用方应使用 ErrGetLib /
 * ErrGetReason 拆分。
 *
 * ERR_LIB_* are the library identifiers (e.g. ERR_LIB_SSL == 20,
 * ERR_LIB_X509 == 11). The ERR_R_* constants are the reason numbers used
 * by SSL and X509. This is the subset the public tls package needs to
 * classify handshake failures; extend as required.
 */
const (
	ErrLibSSL  = 20 // ERR_LIB_SSL
	ErrLibX509 = 11 // ERR_LIB_X509
)

// X509 / SSL 错误 reason（openssl err.h 中的 ERR_R_*）。
//
// 这些是本项目代码路径下实际出现的 reason；新增分类时可按需补充。
//
// X509 / SSL error reason numbers actually seen on this project's code
// paths. Add more as classification grows.
const (
	SSL_R_NO_SHARED_CIPHER      = 158 // no shared cipher
	SSL_R_NO_CIPHERS_AVAILABLE  = 229 // no ciphers available for max version
	SSL_R_UNSUPPORTED_PROTOCOL  = 258 // unsupported protocol
	SSL_R_VERSION_TOO_LOW       = 166 // version too low
	SSL_R_WRONG_SSL_VERSION     = 267 // wrong version number
	SSL_R_BAD_LEGACY_VERSION    = 928 // legacy_version in ClientHello out of range
	X509_R_CERT_VERIFY_FAILED   = 101 // X509_verify_cert failed
)
