package native

/*
#include <openssl/crypto.h>
#include <stdlib.h>
*/
import "C"

// OpenSSLVersionText 返回铜锁版本字符串（如 "Tongsuo 8.5.0-pre1 ..."）。
func OpenSSLVersionText() string {
	p := C.OpenSSL_version(0)
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// OpenSSLVersionNum 返回版本数字（OpenSSL_version_num）。
func OpenSSLVersionNum() uint64 {
	return uint64(C.OpenSSL_version_num())
}

// TongsuoVersionNum 返回铜锁版本数字（Tongsuo_version_num）。
func TongsuoVersionNum() uint64 {
	return uint64(C.Tongsuo_version_num())
}
