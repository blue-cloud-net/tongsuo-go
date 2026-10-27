package core

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// AlgKind 标识算法族，用于枚举 provider 提供的算法名。
//
// AlgKind identifies an algorithm family when enumerating the names
// provided by the loaded providers.
type AlgKind int

// 支持的算法族。
//
// The supported algorithm families.
const (
	// AlgKindMD 标识消息摘要算法。
	//
	// AlgKindMD identifies message-digest algorithms.
	AlgKindMD AlgKind = AlgKind(native.AlgKindMD)
	// AlgKindCipher 标识对称加密算法。
	//
	// AlgKindCipher identifies symmetric ciphers.
	AlgKindCipher AlgKind = AlgKind(native.AlgKindCipher)
	// AlgKindMAC 标识消息认证码算法。
	//
	// AlgKindMAC identifies message authentication codes.
	AlgKindMAC AlgKind = AlgKind(native.AlgKindMAC)
	// AlgKindKDF 标识密钥派生算法。
	//
	// AlgKindKDF identifies key-derivation functions.
	AlgKindKDF AlgKind = AlgKind(native.AlgKindKDF)
	// AlgKindSignature 标识签名算法。
	//
	// AlgKindSignature identifies signature algorithms.
	AlgKindSignature AlgKind = AlgKind(native.AlgKindSignature)
	// AlgKindKeyExch 标识密钥交换算法。
	//
	// AlgKindKeyExch identifies key-exchange algorithms.
	AlgKindKeyExch AlgKind = AlgKind(native.AlgKindKeyExch)
	// AlgKindKEM 标识密钥封装机制。
	//
	// AlgKindKEM identifies key-encapsulation mechanisms.
	AlgKindKEM AlgKind = AlgKind(native.AlgKindKEM)
)

// AlgNames 枚举当前已加载 provider 提供的算法规范名。
// kind 取 AlgKind* 常量；返回的列表未去重，顺序由 provider 决定。
//
// AlgNames enumerates the canonical names of the algorithms provided by the
// currently loaded providers. kind is one of the AlgKind* constants. The
// returned list is not de-duplicated and its order follows the provider.
func AlgNames(kind AlgKind) []string {
	return native.AlgNames(int(kind))
}

// ProviderInfo 描述一个活跃 provider。
//
// ProviderInfo describes one active provider.
type ProviderInfo struct {
	// Name 是 provider 名称（如 "default"）。
	//
	// Name is the provider name (for example "default").
	Name string
	// Version 是 provider 版本号。
	//
	// Version is the provider version string.
	Version string
	// Status 是运行状态（"active" / "inactive"）。
	//
	// Status is the run status ("active" / "inactive").
	Status string
}

// Providers 列出当前活跃的 provider。
//
// Providers lists the currently active providers.
func Providers() []ProviderInfo {
	entries := native.Providers()
	out := make([]ProviderInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, ProviderInfo{
			Name:    e.Name,
			Version: e.Version,
			Status:  e.Status,
		})
	}
	return out
}

// SeedingSource 返回随机数种子来源描述（如 "getrandom"）。
// 本机构建不支持该查询时返回空串。
//
// SeedingSource returns the description of the random seed source (for
// example "getrandom"). It returns an empty string when the build does not
// support the query.
func SeedingSource() string {
	return native.SeedingSource()
}

// TLSGroups 列出本机构建实现的 TLS 组名。
//
// TLSGroups lists the TLS group names implemented by this build.
func TLSGroups() []string {
	return native.TLSGroupNames()
}

// TLSGroupsSupported 报告当前构建是否支持枚举 TLS 组。
// 不支持时 TLSGroups 返回空列表（Tongsuo 8.4.0 / OpenSSL < 3.2）。
//
// TLSGroupsSupported reports whether the current build can enumerate TLS
// groups. When it cannot, TLSGroups returns an empty list (Tongsuo 8.4.0
// / OpenSSL < 3.2).
func TLSGroupsSupported() bool { return native.SSLGroupsSupported() }
