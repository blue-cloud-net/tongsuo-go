package meta

import "github.com/blue-cloud-net/tongsuo-go/internal/native"

// Version 返回铜锁完整版本 banner 第一行（如 "OpenSSL 3.5.4 3 Aug 2026"）。
// 对应 tongsuo version（无 -a）；等价 C 侧 OpenSSL_version(OPENSSL_VERSION)。
// 注意 Tongsuo 8.x 的 banner 第一行只含 OpenSSL 版本字符串，要获取 Tongsuo
// 自身版本请看 VersionString。
//
// Version returns the first line of the Tongsuo version banner (for
// example "OpenSSL 3.5.4 3 Aug 2026"), matching `tongsuo version` without
// -a. Equivalent to C-side OpenSSL_version(OPENSSL_VERSION). Note: on
// Tongsuo 8.x the first line carries only the OpenSSL version string;
// use VersionString to read the Tongsuo-specific identifier.
func Version() string {
	return native.OpenSSLVersionText()
}

// VersionString 返回纯版本号字符串（如 "3.5.4"）。
// 直接调 OpenSSL_version(OPENSSL_VERSION_STRING) 拿最简短的版本号；
// 不含产品名前缀与构建日期。若铜锁未加载返回空串。
//
// VersionString returns the bare version string (for example "3.5.4").
// It directly invokes OpenSSL_version(OPENSSL_VERSION_STRING) to read
// the shortest version form without product-name prefix or build date;
// returns "" if the library reports nothing.
func VersionString() string {
	return native.OpenSSLVersionWithIndex(native.VersionString)
}

// VersionNum 返回 OpenSSL 兼容版本号（OpenSSL_version_num）。
// 数字格式与 OpenSSL 一致，例如 0x30500040f（3.5.4 final）。
// 在原生 OpenSSL 与 Tongsuo 之间数值相同。
//
// VersionNum returns the OpenSSL-compatible version number
// (OpenSSL_version_num). The packed format matches OpenSSL, e.g.
// 0x30500040f for 3.5.4 final. The value is identical between
// native OpenSSL and Tongsuo.
func VersionNum() uint64 {
	return native.OpenSSLVersionNum()
}

// TongsuoVersionNum 返回铜锁自有版本号（Tongsuo_version_num）。
// 在 Tongsuo 上为非零值（与 VersionNum 协调区分 Tongsuo / OpenSSL）；
// 在原生 OpenSSL 上通常为 0。
//
// TongsuoVersionNum returns the Tongsuo-specific version number
// (Tongsuo_version_num). It is non-zero on Tongsuo (with VersionNum
// disambiguating Tongsuo vs OpenSSL); usually 0 on stock OpenSSL.
func TongsuoVersionNum() uint64 {
	return native.TongsuoVersionNum()
}
