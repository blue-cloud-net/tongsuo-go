package meta

import (
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// BuildInfo 汇总铜锁构建与运行环境快照，对应 tongsuo version -a 的输出。
//
// 各字段值就是 OpenSSL_version(idx) 的原始返回值——Tongsuo 8.x 已经
// 在返回值里带好前缀（如 "OPENSSLDIR: \"...\""），本结构体**不再加前缀**，
// 拼接时直接逐行输出即可。
// 字段未取到时为空串（OpenSSL_version 对应 index 不被某些 build 支持时
// 返回空串）；ReadBuildInfo 不会因单字段缺失而整体失败。
//
// BuildInfo aggregates a snapshot of Tongsuo's build and runtime
// environment, matching the output of `tongsuo version -a`. Each field
// holds the raw value returned by OpenSSL_version(idx); Tongsuo 8.x
// already prefixes values such as "OPENSSLDIR: \"...\"" so this type
// does NOT add a prefix when formatting. Fields whose index is not
// supported by a particular build resolve to "".
type BuildInfo struct {
	Version           string // 完整 banner 第一行
	VersionString     string // 纯版本号（OPENSSL_VERSION_STRING）
	VersionNum        uint64 // OpenSSL_version_num
	TongsuoVersionNum uint64 // Tongsuo_version_num；原生 OpenSSL 上通常为 0
	Compiler          string // OPENSSL_CFLAGS
	BuiltOn           string // OPENSSL_BUILT_ON
	Platform          string // OPENSSL_PLATFORM
	OpenSSLDir        string // OPENSSL_DIR（含 OPENSSLDIR: 前缀）
	EnginesDir        string // OPENSSL_ENGINES_DIR（含 ENGINESDIR: 前缀）
	ModulesDir        string // OPENSSL_MODULES_DIR（含 MODULESDIR: 前缀）
	CPUInfo           string // OPENSSL_CPU_INFO（含 CPUINFO: 前缀）
}

// ReadBuildInfo 一次性读取铜锁的全部构建与运行环境快照。
// 对应 tongsuo version -a；本函数**不返回错误**——所有字段取值失败时
// 退化为空串或零值。
//
// ReadBuildInfo reads a one-shot snapshot of the Tongsuo build and
// runtime environment, matching `tongsuo version -a`. It never returns
// an error: fields that fail to resolve degrade to "" (or 0 for the
// numeric ones).
func ReadBuildInfo() *BuildInfo {
	bi := &BuildInfo{
		Version:           Version(),
		VersionString:     VersionString(),
		VersionNum:        VersionNum(),
		TongsuoVersionNum: TongsuoVersionNum(),
		Compiler:          native.OpenSSLVersionWithIndex(native.VersionCFlags),
		BuiltOn:           native.OpenSSLVersionWithIndex(native.VersionBuiltOn),
		Platform:          native.OpenSSLVersionWithIndex(native.VersionPlatform),
		OpenSSLDir:        native.OpenSSLVersionWithIndex(native.VersionDir),
		EnginesDir:        native.OpenSSLVersionWithIndex(native.VersionEngines),
		ModulesDir:        native.OpenSSLVersionWithIndex(native.VersionModules),
		CPUInfo:           native.OpenSSLVersionWithIndex(native.VersionCPUInfo),
	}
	return bi
}

// String 以 tongsuo version -a 的排版返回 BuildInfo 的多行文本视图。
// 字段值已由铜锁带好前缀；本方法只做按顺序拼接并跳过空字段。
// 输出**不带**末尾换行（CLI 输出虽带换行，但 godoc / fmt 场景更友好）。
//
// String formats the BuildInfo as the multi-line text view produced
// by `tongsuo version -a`. Values already carry their CLI prefixes;
// this method only sequences them and skips empty fields. The output
// has no trailing newline.
func (bi *BuildInfo) String() string {
	if bi == nil {
		return ""
	}
	lines := []string{
		bi.Version,
		bi.VersionString,
		bi.Compiler,
		bi.BuiltOn,
		bi.Platform,
		bi.OpenSSLDir,
		bi.EnginesDir,
		bi.ModulesDir,
		bi.CPUInfo,
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
