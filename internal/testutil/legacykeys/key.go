// Package legacykeys 提供 x509 包遗留测试的**迁移期**密钥替身类型。
//
// 背景：x509 的测试体共 2600+ 行，其中 73 处通过 `crypto/sm2` / `crypto/rsa` /
// `crypto/ecdsa` / `crypto/ed25519` / `crypto/ed448` 的 `GenerateKey` 生成密钥，
// 并把结果直接传给 x509 的公开入口。roadmap commit 19c 把那些入口的参数类型从
// 已删除的 `x509.PublicKey` / `x509.PrivateKey` 窄接口换成 `asym.PublicKey` /
// `asym.PrivateKey` 后，这些调用点全部失效。
//
// 为了**避免同时改写 73 处重复度极高的调用点**（`priv, _ := sm2.GenerateKey()`
// 一类文本各出现 7～12 次，无法用唯一上下文逐条替换），本包提供一个包装类型：
//
//   - 内嵌 `asym.PrivateKey`，因此天然满足 `asym.PrivateKey` 的全部方法；
//   - 额外暴露 `Key() *core.PKey`，让遗留的 `priv.Key()` 调用点继续编译；
//   - 额外暴露 `CorePKey() *core.PKey`，让 `internal/keyaccess` 在包装类型上
//     同样命中（否则 x509 的 `corePublicKey` / `corePrivateKey` 会取不到句柄）。
//
// 子包 `legacykeys/{sm2,rsa,ecdsa,ed25519,ed448}` 各提供一个与已删除的
// `crypto/*` 同名的 `GenerateKey`，从而只需替换测试文件的 import 路径即可编译。
//
// ⚠️ 本包**仅供测试**，不属于公开 API。正确做法是后续把遗留测试体逐步改写为直接
// 调用 `asym.GenerateSM2` / `asym.GenerateRSA` 等，届时删除本包（见
// docs/refactor-roadmap.md §13 的 19c 备注）。
//
// Package legacykeys provides migration-period key stand-ins for the legacy x509
// test suite. It is test-only, not public API, and is meant to be deleted once the
// legacy test bodies are rewritten to call asym directly.
package legacykeys

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
)

// Key 包装一把 asym 私钥，并额外暴露遗留测试需要的句柄访问方法。
//
// 内嵌的 `asym.PrivateKey` 提供 `Algorithm` / `Public` / `MarshalPrivateKeyPEM`，
// 因此 *Key 可直接用于任何收 `asym.PrivateKey` 的入口。
//
// Key wraps an asym private key and additionally exposes the handle accessors the
// legacy tests rely on.
//
// The embedded asym.PrivateKey supplies Algorithm / Public /
// MarshalPrivateKeyPEM, so a *Key can be passed to any entry point taking an
// asym.PrivateKey.
type Key struct {
	asym.PrivateKey
	handle *core.PKey
}

// Wrap 把 asym 私钥包装为 *Key，并缓存其底层句柄。
//
// priv 须由本库的 asym 算法入口生成/加载；无法取到句柄时返回错误。
//
// Wrap wraps an asym private key as a *Key, caching its underlying handle.
func Wrap(priv asym.PrivateKey, err error) (*Key, error) {
	if err != nil {
		return nil, err
	}
	if priv == nil {
		return nil, fmt.Errorf("legacykeys: nil private key")
	}
	h, ok := keyaccess.PKey(priv)
	if !ok || h == nil {
		return nil, fmt.Errorf("legacykeys: no native handle for %T", priv)
	}
	return &Key{PrivateKey: priv, handle: h}, nil
}

// Key 返回底层句柄，供遗留测试的 `priv.Key()` 调用点使用。
//
// 句柄仍由被包装的 asym 私钥持有，本方法只是借用（配合 x509 测试里的
// asX509PubKey / asX509PrivKey 助手做 PEM 往返）。
//
// Key returns the underlying handle for the legacy `priv.Key()` call sites.
//
// The handle is still owned by the wrapped asym private key; this accessor only
// borrows it (used together with the asX509PubKey / asX509PrivKey helpers in the
// x509 tests, which perform a PEM round trip).
func (k *Key) Key() *core.PKey { return k.handle }

// CorePKey 让 internal/keyaccess 的结构化断言在包装类型上同样命中。
//
// 必须显式提供：`CorePKey()` 只存在于 asym 的**具体类型**上、不在
// `asym.PrivateKey` 接口里，因此无法经内嵌接口提升获得。
//
// CorePKey makes the internal/keyaccess structural assertion hit on the wrapper
// type as well.
//
// It must be spelled out because CorePKey() exists only on asym's concrete types,
// not on the asym.PrivateKey interface, so it cannot be promoted through the
// embedded interface.
func (k *Key) CorePKey() *core.PKey { return k.handle }

// Public 返回配对公钥（转发到被包装的 asym 私钥）。
//
// Public returns the paired public key, forwarded to the wrapped asym private key.
func (k *Key) Public() asym.PublicKey { return k.PrivateKey.Public() }

// LoadPrivateKeyPEM 从 PEM 加载私钥并包装为 *Key（等价原 crypto/*.LoadPrivateKeyPEM）。
//
// LoadPrivateKeyPEM loads a private key from PEM and wraps it as a *Key.
func LoadPrivateKeyPEM(pemBytes []byte) (*Key, error) {
	return Wrap(asym.LoadPrivateKeyPEM(pemBytes))
}

// LoadPublicKeyPEM 从 PEM 加载公钥（等价原 crypto/*.LoadPublicKeyPEM）。
//
// LoadPublicKeyPEM loads a public key from PEM.
func LoadPublicKeyPEM(pemBytes []byte) (asym.PublicKey, error) {
	return asym.LoadPublicKeyPEM(pemBytes)
}
