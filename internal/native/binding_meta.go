package native

/*
#include "shim.h"
*/
import "C"
import (
	"strings"
	"unsafe"
)

// 算法族枚举种类：与 shim.h 的 X_ALG_KIND_* 一一对应。
//
// Algorithm family kinds mirroring the X_ALG_KIND_* constants in shim.h.
const (
	// AlgKindMD 表示消息摘要算法族。
	//
	// AlgKindMD selects the message-digest family.
	AlgKindMD = C.X_ALG_KIND_MD
	// AlgKindCipher 表示对称加密算法族。
	//
	// AlgKindCipher selects the symmetric cipher family.
	AlgKindCipher = C.X_ALG_KIND_CIPHER
	// AlgKindMAC 表示消息认证码算法族。
	//
	// AlgKindMAC selects the MAC family.
	AlgKindMAC = C.X_ALG_KIND_MAC
	// AlgKindKDF 表示密钥派生算法族。
	//
	// AlgKindKDF selects the KDF family.
	AlgKindKDF = C.X_ALG_KIND_KDF
	// AlgKindSignature 表示签名算法族。
	//
	// AlgKindSignature selects the signature family.
	AlgKindSignature = C.X_ALG_KIND_SIGNATURE
	// AlgKindKeyExch 表示密钥交换算法族。
	//
	// AlgKindKeyExch selects the key-exchange family.
	AlgKindKeyExch = C.X_ALG_KIND_KEYEXCH
	// AlgKindKEM 表示密钥封装机制算法族。
	//
	// AlgKindKEM selects the KEM family.
	AlgKindKEM = C.X_ALG_KIND_KEM
)

// AlgNames 枚举当前已加载 provider 提供的算法规范名。
// kind 取 AlgKind* 常量；返回去重前的原始列表（顺序由 provider 决定）。
// 无可用算法时返回空切片（非 nil）。
//
// AlgNames enumerates the canonical names of the algorithms provided by the
// currently loaded providers. kind is one of the AlgKind* constants. The
// returned slice is the raw (not yet de-duplicated) list in provider order;
// it is empty rather than nil when no algorithm is available.
func AlgNames(kind int) []string {
	raw := C.X_EVP_alg_names(C.int(kind))
	if raw == nil {
		return []string{}
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(raw))
	return strings.Split(C.GoString(raw), "\n")
}

// ProviderEntry 描述一个活跃 provider。
//
// ProviderEntry describes one active provider.
type ProviderEntry struct {
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
// 返回空切片（非 nil）表示没有可用 provider。
//
// Providers lists the currently active providers. It returns an empty slice
// (not nil) when no provider is available.
func Providers() []ProviderEntry {
	raw := C.X_OSSL_provider_list()
	if raw == nil {
		return []ProviderEntry{}
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(raw))
	out := []ProviderEntry{}
	for _, line := range strings.Split(C.GoString(raw), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		e := ProviderEntry{}
		if len(parts) > 0 {
			e.Name = parts[0]
		}
		if len(parts) > 1 {
			e.Version = parts[1]
		}
		if len(parts) > 2 {
			e.Status = parts[2]
		}
		out = append(out, e)
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
	p := C.X_OPENSSL_seed_source()
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// TLSGroupNames 列出本机构建实现的 TLS 组名。
// 返回空切片（非 nil）表示没有可用组。
//
// TLSGroupNames lists the TLS group names implemented by this build. It
// returns an empty slice (not nil) when no group is available.
func TLSGroupNames() []string {
	raw := C.X_SSL_group_names()
	if raw == nil {
		return []string{}
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(raw))
	return strings.Split(C.GoString(raw), "\n")
}
