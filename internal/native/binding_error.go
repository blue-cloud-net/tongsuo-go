package native

/*
#include <openssl/err.h>
#include <stdlib.h>
*/
import "C"

// PopError 从错误队列取出并返回一个错误码；队列为空返回 0。
//
// PopError wraps ERR_get_error; it pops the earliest error code from the
// current thread's OpenSSL error queue. Returns 0 when the queue is empty.
func PopError() uint64 {
	return uint64(C.ERR_get_error())
}

// ErrorString 返回错误码对应的错误描述字符串。
// 使用 ERR_error_string_n（线程安全，写入本地缓冲区）。
//
// ErrorString wraps the thread-safe ERR_error_string_n; the description is
// written into a 256-byte stack buffer, so codes producing longer text are
// truncated. Pass an error code from PopError.
func ErrorString(code uint64) string {
	var buf [256]C.char
	C.ERR_error_string_n(C.ulong(code), &buf[0], C.size_t(len(buf)))
	return C.GoString(&buf[0])
}
