// Package keyaccess 提供跨包获取非对称密钥底层 *core.PKey 的桥接机制。
//
// 本包的设计动机见 docs/refactor-roadmap.md §5.2：
//
//  1. asym 包的具体类型（如 *sm2PrivateKey、*rsaPrivateKey）一律非导出，
//     因此不能在任何对外接口中暴露 CorePKey() 方法；
//  2. ecdh / x509 / tls / jwk / pkcs12 等消费方又必须拿到底层 *core.PKey
//     （用于 EVP_PKEY_derive / X509_set_pubkey / X509_sign / PEM_write_bio_PrivateKey 等）；
//  3. 消费方又不能直接 import asym（会与 x509 → asym 单向依赖冲突）；
//  4. 不能在 internal/core 写「类型开关」反查公开类型（核心层位于依赖最底层，
//     import asym 会成环）。
//
// 方案：用结构化接口满足 + 集中断言点。消费方把任意 asym 密钥传入 PKey()，
// 本包通过 interface{ CorePKey() *core.PKey }（asym 具体类型）或
// interface{ Key() *core.PKey }（过渡期 key 包类型）做类型断言；
// **取到后必须立即调用 (*core.PKey).Dup() 复制一份**，以免源密钥
// Close 后消费方拿到悬垂指针（roadmap §10 风险项）。
//
// asym 包已落地（roadmap commit 10～17），其具体类型统一实现
// CorePKey() *core.PKey（见 asym/corepkey.go）。Key() *core.PKey 形状
// 仅用于兼容尚未删除的 key 包，将在 roadmap commit 21 移除。
//
// Package keyaccess provides a bridge for retrieving the underlying
// *core.PKey handle from any asym package private key type without
// breaking the dependency direction.
//
// See docs/refactor-roadmap.md §5.2 for the full rationale. In short:
// asym's concrete types are unexported, so the CorePKey() accessor cannot
// appear on any public interface; yet ecdh / x509 / tls / jwk / pkcs12
// need the underlying *core.PKEY for EVP_PKEY_derive, X509_set_pubkey,
// X509_sign, PEM_write_bio_PrivateKey, etc. This package centralises the
// type assertion and reminds every caller to Dup() the result so the
// source key's Close does not leave a dangling pointer.
//
// The two accepted shapes are CorePKey() *core.PKey (asym's concrete
// types, see asym/corepkey.go) and Key() *core.PKey (transitional key
// package types, removed in roadmap commit 21). This package centralises
// the type assertion and reminds every caller to Dup() the result so the
// source key's Close does not leave a dangling pointer.
package keyaccess

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// pkeyHolder 是持有一个底层 *core.PKey 句柄的对象所应满足的两种形状之一。
//
// asym 包的具体类型实现 CorePKey() *core.PKey（见 asym/corepkey.go）；
// 过渡期的 key 包类型实现 Key() *core.PKey。两种形状都支持，
// 待 key 包删除（roadmap commit 21）后只保留 CorePKey。
//
// pkeyHolder is one of the two structural shapes an object holding a
// *core.PKey may satisfy. asym's concrete types implement
// CorePKey() *core.PKey (see asym/corepkey.go); the transitional key
// package types implement Key() *core.PKey. Both shapes are accepted;
// once the key package is deleted (roadmap commit 21) only CorePKey remains.
type pkeyHolder interface {
	Key() *core.PKey
}

// corePKeyHolder 是 asym 包具体类型满足的形状。
//
// corePKeyHolder is the shape satisfied by asym's concrete key types.
type corePKeyHolder interface {
	CorePKey() *core.PKey
}

// PKey 从任意 asym（或过渡期 key 包）密钥对象取出底层 *core.PKey。
//
// 第二个返回值报告断言是否成功：失败时不返回错误而是返回 (nil, false)，
// 让调用方在「不期望该类型持原生句柄」时无须 error 处理。
//
// **重要契约**：取到的 *core.PKey 由源对象持有生命周期，**调用方必须立即**
// 调用 (*core.PKey).Dup() 复制一份后再使用；源对象 Close 后原句柄即失效。
//
// 若 v 本身就是 *core.PKey，则直接返回 (v, true)，无需 Dup（因为 v 本身
// 就是独立的句柄）。
//
// PKey extracts the underlying *core.PKey from any asym (or transitional
// key) key object.
//
// The second return value reports assertion success; callers that do not
// expect a value to hold a native handle can simply skip without error
// handling.
//
// **Important contract**: the returned *core.PKey is owned by the source
// value; callers MUST call (*core.PKey).Dup() immediately before using
// the handle, otherwise the source value's Close will leave a dangling
// pointer. This rule is the central reason this package exists.
//
// If v is already a *core.PKey, it is returned as-is (no Dup needed,
// because v is itself an independent handle).
func PKey(v any) (*core.PKey, bool) {
	switch k := v.(type) {
	case *core.PKey:
		return k, true
	case corePKeyHolder:
		return k.CorePKey(), true
	case pkeyHolder:
		return k.Key(), true
	}
	return nil, false
}
