package meta

import (
	"sort"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// ProviderInfo 描述一个活跃的 provider。
//
// ProviderInfo describes one active provider.
type ProviderInfo struct {
	// Name 是 provider 短名（如 "default"）。
	//
	// Name is the short provider name (for example "default").
	Name string
	// Version 是 provider 版本号（如 "3.5.4"）。
	//
	// Version is the provider version string (for example "3.5.4").
	Version string
	// Status 是运行状态（"active" / "inactive"）。
	//
	// Status is the run status ("active" / "inactive").
	Status string
}

// algNames 返回指定算法族的规范名列表（去重 + 字典序）。
// 列表内容取决于当前已加载的 provider。
//
// algNames returns the canonical names of one algorithm family, de-duplicated
// and sorted. The content depends on the currently loaded providers.
func algNames(kind int) []string {
	raw := core.AlgNames(kind)
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, n := range raw {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Digests 返回当前 provider 提供的消息摘要算法名。
// 对应 `tongsuo list -digest-algorithms`；返回的列表已去重并按字典序排列。
//
// Digests returns the message-digest algorithm names provided by the current
// providers, matching `tongsuo list -digest-algorithms`. The returned list
// is de-duplicated and sorted lexicographically.
func Digests() []string {
	return algNames(native.AlgKindMD)
}

// Ciphers 返回当前 provider 提供的对称加密算法名。
// 对应 `tongsuo list -cipher-algorithms`；返回的列表已去重并按字典序排列。
//
// Ciphers returns the symmetric cipher algorithm names provided by the
// current providers, matching `tongsuo list -cipher-algorithms`. The
// returned list is de-duplicated and sorted lexicographically.
func Ciphers() []string {
	return algNames(native.AlgKindCipher)
}

// MACs 返回当前 provider 提供的消息认证码算法名。
// 对应 `tongsuo list -mac-algorithms`；返回的列表已去重并按字典序排列。
//
// MACs returns the MAC algorithm names provided by the current providers,
// matching `tongsuo list -mac-algorithms`. The returned list is
// de-duplicated and sorted lexicographically.
func MACs() []string {
	return algNames(native.AlgKindMAC)
}

// KDFs 返回当前 provider 提供的密钥派生算法名。
// 对应 `tongsuo list -kdf-algorithms`；返回的列表已去重并按字典序排列。
//
// KDFs returns the key-derivation algorithm names provided by the current
// providers, matching `tongsuo list -kdf-algorithms`. The returned list is
// de-duplicated and sorted lexicographically.
func KDFs() []string {
	return algNames(native.AlgKindKDF)
}

// Signatures 返回当前 provider 提供的签名算法名。
// 对应 `tongsuo list -signature-algorithms`；返回的列表已去重并按字典序排列。
//
// Signatures returns the signature algorithm names provided by the current
// providers, matching `tongsuo list -signature-algorithms`. The returned
// list is de-duplicated and sorted lexicographically.
func Signatures() []string {
	return algNames(native.AlgKindSignature)
}

// KeyExchanges 返回当前 provider 提供的密钥交换算法名。
// 对应 `tongsuo list -key-exchange-algorithms`；返回的列表已去重并按字典序排列。
//
// KeyExchanges returns the key-exchange algorithm names provided by the
// current providers, matching `tongsuo list -key-exchange-algorithms`. The
// returned list is de-duplicated and sorted lexicographically.
func KeyExchanges() []string {
	return algNames(native.AlgKindKeyExch)
}

// KEMs 返回当前 provider 提供的密钥封装机制算法名。
// 对应 `tongsuo list -kem-algorithms`；返回的列表已去重并按字典序排列。
//
// KEMs returns the key-encapsulation-mechanism algorithm names provided by
// the current providers, matching `tongsuo list -kem-algorithms`. The
// returned list is de-duplicated and sorted lexicographically.
func KEMs() []string {
	return algNames(native.AlgKindKEM)
}

// TLSGroups 返回当前构建实现的 TLS 组名。
// 对应 `tongsuo list -tls-groups`；返回的列表已去重并按字典序排列。
//
// TLSGroups returns the TLS group names implemented by the current build,
// matching `tongsuo list -tls-groups`. The returned list is
// de-duplicated and sorted lexicographically.
func TLSGroups() []string {
	raw := core.TLSGroups()
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, g := range raw {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Providers 返回当前活跃的 provider 列表。
// 对应 `tongsuo list -providers`；本库不主动加载 legacy provider，
// 因此结果只反映调用时刻已加载的 provider。
//
// Providers returns the currently active providers, matching
// `tongsuo list -providers`. This library never loads the legacy
// provider on its own, so the result reflects only the providers that
// are loaded at call time.
func Providers() []ProviderInfo {
	entries := core.Providers()
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

// SeedingSource 返回随机数种子来源描述（如 "os-specific"）。
// 对应 `tongsuo version -a` 的 "Seeding source" 行；本机构建不支持该查询
// 时返回空串。
//
// SeedingSource returns the description of the random seed source (for
// example "os-specific"), matching the "Seeding source" line of
// `tongsuo version -a`. It returns an empty string when the build does
// not support the query.
func SeedingSource() string {
	return core.SeedingSource()
}
