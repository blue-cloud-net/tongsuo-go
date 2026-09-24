package asym

import "github.com/blue-cloud-net/tongsuo-go/internal/core"

// 本文件集中声明各非导出密钥具体类型上的导出方法 `CorePKey()`。
//
// 该契约是 `internal/keyaccess` 结构化断言（`interface{ CorePKey() *core.PKey }`）
// 的落点：包外消费方（ecdh / x509 / tls / jwk / pkcs/pkcs12）据此取到底层
// `*core.PKey`，取到后**必须**立即 `EVP_PKEY_dup` 复制，否则源密钥 Close 后即成
// 悬垂句柄。
//
// 为何方法名导出而类型不导出：Go 的非导出标识符带包限定，包外无法满足
// `corePKey()` 这类方法；只有导出名才能被其它包的结构化接口断言命中。而宿主
// 类型非导出，因此这些方法不会出现在 `go doc -all ./asym` 的公开面中（见
// docs/refactor-roadmap.md §5.2 验收：`grep -c CorePKey` 应为 0）。
//
// 该契约**不进入任何导出接口**（`Key` / `PrivateKey` / `PublicKey` 均无此方法），
// 以免它变成公开 API 的一部分。
//
// This file declares the exported `CorePKey()` method on every unexported
// concrete key type in one place.
//
// The method is the anchor for the internal/keyaccess structural assertion
// (`interface{ CorePKey() *core.PKey }`): out-of-package consumers (ecdh /
// x509 / tls / jwk / pkcs/pkcs12) use it to reach the underlying *core.PKey
// and MUST immediately copy it with EVP_PKEY_dup, otherwise the source key's
// Close leaves a dangling handle.
//
// Why the method name is exported while the type is not: unexported Go
// identifiers are package-qualified, so an out-of-package structural
// assertion can never satisfy `corePKey()`; only an exported name works.
// Because the host types are unexported, these methods never appear in the
// public surface of `go doc -all ./asym` (see docs/refactor-roadmap.md §5.2
// acceptance: `grep -c CorePKey` must be 0).
//
// The contract is deliberately kept out of every exported interface
// (`Key` / `PrivateKey` / `PublicKey` do not carry it) so that it never
// becomes part of the public API.

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
// 取到后必须立即 Dup 再使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion. Callers must copy it with Dup
// before use.
func (k *sm2PrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *sm2PublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *rsaPrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *rsaPublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *ecPrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *ecPublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *ed25519PrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *ed25519PublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *ed448PrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *ed448PublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *x25519PrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *x25519PublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *x448PrivateKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// CorePKey 返回底层核心密钥句柄，供 internal/keyaccess 结构化断言使用。
//
// CorePKey returns the underlying core key handle for the
// internal/keyaccess structural assertion.
func (k *x448PublicKey) CorePKey() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}
