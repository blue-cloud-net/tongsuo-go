package native

/*
#include <openssl/rand.h>
*/
import "C"
import "unsafe"

// RAND_bytes_ex 生成 len(buf) 个加密安全随机字节写入 buf。
// RAND_bytes_ex fills buf with len(buf) cryptographically secure random bytes.
// Returns false on error (consult the OpenSSL error queue). An empty buf is
// treated as success and returns true without calling the C layer.
func RAND_bytes_ex(buf []byte) bool {
	if len(buf) == 0 {
		return true
	}
	return C.RAND_bytes_ex(nil, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), 0) == 1
}
