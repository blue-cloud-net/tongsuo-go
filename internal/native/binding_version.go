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

// OpenSSLVersionInfo 枚举了 OpenSSL_version 可接受的 index 参数。
//
// OpenSSLVersionInfo enumerates the indices accepted by OpenSSL_version.
type OpenSSLVersionInfo int

// OpenSSL_version 的 index 常量，参考 openssl/crypto.h。
// Index constants for OpenSSL_version, taken from openssl/crypto.h.
const (
	VersionBanner   OpenSSLVersionInfo = 0 // OPENSSL_VERSION
	VersionCFlags   OpenSSLVersionInfo = 1 // OPENSSL_CFLAGS
	VersionBuiltOn  OpenSSLVersionInfo = 2 // OPENSSL_BUILT_ON
	VersionPlatform OpenSSLVersionInfo = 3 // OPENSSL_PLATFORM
	VersionDir      OpenSSLVersionInfo = 4 // OPENSSL_DIR
	VersionEngines  OpenSSLVersionInfo = 5 // OPENSSL_ENGINES_DIR
	VersionString   OpenSSLVersionInfo = 6 // OPENSSL_VERSION_STRING
	VersionModules  OpenSSLVersionInfo = 8 // OPENSSL_MODULES_DIR（OPENSSL_MODULES = 7 为废弃别名）
	VersionCPUInfo  OpenSSLVersionInfo = 9 // OPENSSL_CPU_INFO
)

// OpenSSLVersionWithIndex 返回 OpenSSL_version(idx) 对应的字符串。
// idx 取 VersionBanner 等常量；返回的字符串由铜锁在编译期固化，C 端若返回 NULL
// 则本函数返回空串。
//
// 安全说明：本函数仅返回铜锁**编译期**固化的元信息（编译器标志、构建主机、
// 平台、库目录、模块目录、CPU 能力等），不涉及用户数据。
//
// OpenSSLVersionWithIndex returns the string returned by OpenSSL_version(idx)
// for the given VersionBanner-style index. The underlying string is fixed at
// Tongsuo build time; if the C side returns NULL, this function returns "".
//
// Safety: this function only returns Tongsuo **build-time** metadata (compiler
// flags, build host, platform, lib directory, modules directory, CPU info,
// etc.) and never touches user data.
func OpenSSLVersionWithIndex(idx OpenSSLVersionInfo) string {
	p := C.OpenSSL_version(C.int(idx))
	if p == nil {
		return ""
	}
	return C.GoString(p)
}
