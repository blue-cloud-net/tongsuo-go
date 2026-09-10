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
