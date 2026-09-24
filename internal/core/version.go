package core

import "github.com/blue-cloud-net/tongsuo-go/internal/native"

// VersionText 返回铜锁版本字符串（如 "Tongsuo 8.5.0-pre1 ..."）。
// 字符串来自 OpenSSL_version，包含完整的 OpenSSL/铜锁构建 banner（编译器与 configure 选项）。
//
// VersionText returns the Tongsuo version string as reported by
// OpenSSL_version (for example "Tongsuo 8.5.0-pre1 ..."). The string
// embeds the full OpenSSL/Tongsuo build banner including compiler and
// configure options.
func VersionText() string { return native.OpenSSLVersionText() }

// VersionNum 返回版本数字（OpenSSL_version_num），类型为 uint64。
// 编码遵循上游约定 <major><minor><fix><patch>（每个字段占一个 nibble），例如 3.0.0 对应 0x030000000。
// 在铜锁构建上该值仍然反映 OpenSSL 谱系。
//
// VersionNum returns the OpenSSL version number (OpenSSL_version_num)
// as a uint64. The encoding follows the upstream convention
// <major><minor><fix><patch> (each nibble), e.g. 0x030000000 for 3.0.0.
// On Tongsuo builds this still reflects the OpenSSL lineage.
func VersionNum() uint64 { return native.OpenSSLVersionNum() }

// TongsuoVersionNum 返回铜锁版本数字（Tongsuo_version_num），类型为 uint64。
// 与 VersionNum 不同，该值反映铜锁分支的发布标识，在铜锁构建上可能不同；在原生 OpenSSL 上通常为 0。
//
// TongsuoVersionNum returns the Tongsuo-specific version number
// (Tongsuo_version_num) as a uint64. Unlike VersionNum this value
// reflects the Tongsuo fork's release identity and may differ on
// Tongsuo builds; on stock OpenSSL it is typically zero.
func TongsuoVersionNum() uint64 { return native.TongsuoVersionNum() }

// VersionString 返回纯版本号字符串（如 "3.5.4"），不含产品名前缀与构建日期。
//
// VersionString returns the bare version string (for example "3.5.4"), without
// product-name prefix or build date.
func VersionString() string {
	return native.OpenSSLVersionWithIndex(native.VersionString)
}

// BuildEnv 汇总铜锁的编译期与运行期环境快照（对应 `tongsuo version -a`）。
//
// 各字段就是 OpenSSL_version(idx) 的原始返回值——铜锁已在返回值里带好前缀
// （如 `OPENSSLDIR: "..."`），本结构体不再加前缀；不支持的 index 退化为空串。
//
// BuildEnv aggregates a snapshot of Tongsuo's build-time and runtime
// environment (matching `tongsuo version -a`).
//
// Each field is the raw OpenSSL_version(idx) value — Tongsuo already prefixes
// values (for example `OPENSSLDIR: "..."`) and this type adds none; unsupported
// indices degrade to the empty string.
type BuildEnv struct {
	// Version 是完整 banner（OPENSSL_VERSION）；VersionString 是纯版本号。
	Version       string
	VersionString string
	// VersionNum / TongsuoVersionNum 为数值版本号。
	VersionNum        uint64
	TongsuoVersionNum uint64
	// Compiler 为 OPENSSL_CFLAGS，BuiltOn 为 OPENSSL_BUILT_ON。
	Compiler string
	BuiltOn  string
	// Platform 为 OPENSSL_PLATFORM。
	Platform string
	// OpenSSLDir / EnginesDir / ModulesDir 为对应目录（已含前缀）。
	OpenSSLDir string
	EnginesDir string
	ModulesDir string
	// CPUInfo 为 OPENSSL_CPU_INFO。
	CPUInfo string
}

// ReadBuildEnv 一次性读取铜锁的编译期与运行期环境快照。
//
// 本函数**不返回错误**：任何字段取不到都退化为空串或零值（与
// `tongsuo version -a` 在信息不全时仍能输出一致）。
//
// ReadBuildEnv reads a one-shot snapshot of Tongsuo's build-time and runtime
// environment.
//
// It never returns an error: fields that cannot be resolved degrade to the
// empty string (or zero), matching `tongsuo version -a` behaviour on partially
// instrumented builds.
func ReadBuildEnv() BuildEnv {
	byIndex := func(idx native.OpenSSLVersionInfo) string {
		return native.OpenSSLVersionWithIndex(idx)
	}
	return BuildEnv{
		Version:           VersionText(),
		VersionString:     VersionString(),
		VersionNum:        VersionNum(),
		TongsuoVersionNum: TongsuoVersionNum(),
		Compiler:          byIndex(native.VersionCFlags),
		BuiltOn:           byIndex(native.VersionBuiltOn),
		Platform:          byIndex(native.VersionPlatform),
		OpenSSLDir:        byIndex(native.VersionDir),
		EnginesDir:        byIndex(native.VersionEngines),
		ModulesDir:        byIndex(native.VersionModules),
		CPUInfo:           byIndex(native.VersionCPUInfo),
	}
}
