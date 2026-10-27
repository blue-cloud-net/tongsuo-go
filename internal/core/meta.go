package core

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// AlgNames 枚举当前已加载 provider 提供的算法规范名。
// kind 取 native.AlgKind* 常量；返回的列表未去重，顺序由 provider 决定。
//
// AlgNames enumerates the canonical names of the algorithms provided by the
// currently loaded providers. kind is one of the native.AlgKind* constants.
// The returned list is not de-duplicated and its order follows the provider.
func AlgNames(kind int) []string {
	return native.AlgNames(kind)
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
