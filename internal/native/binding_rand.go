package native

/*
#include <openssl/rand.h>
*/
import "C"
import "unsafe"

// RAND_bytes 生成 len(buf) 个加密安全随机字节写入 buf。
func RAND_bytes(buf []byte) bool {
	if len(buf) == 0 {
		return true
	}
	return C.RAND_bytes((*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf))) == 1
}
