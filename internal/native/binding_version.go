package native

/*
#include <openssl/crypto.h>
#include <stdlib.h>
*/
import "C"

// OpenSSLVersionText 返回铜锁版本字符串（如 "Tongsuo 8.5.0-pre1 ..."）。
// OpenSSLVersionText wraps OpenSSL_version(OPENSSL_VERSION); it returns the
// human-readable Tongsuo/OpenSSL banner string or "" if the C pointer is NULL.
func OpenSSLVersionText() string {
	p := C.OpenSSL_version(0)
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// OpenSSLVersionNum 返回版本数字（OpenSSL_version_num）。
// OpenSSLVersionNum wraps OpenSSL_version_num and returns the packed release
// version (e.g. 0x1010107f for 1.1.1g).
func OpenSSLVersionNum() uint64 {
	return uint64(C.OpenSSL_version_num())
}

// TongsuoVersionNum 返回铜锁版本数字（Tongsuo_version_num）。
// TongsuoVersionNum wraps Tongsuo_version_num, the Tongsuo-specific version
// number defined by the bundled library.
func TongsuoVersionNum() uint64 {
	return uint64(C.Tongsuo_version_num())
}
