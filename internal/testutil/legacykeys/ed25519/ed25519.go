// Package ed25519 是 x509 遗留测试的迁移期替身，签名对齐已删除的 crypto/ed25519。
//
// 仅测试使用；用法与删除时机见 internal/testutil/legacykeys 的包文档。
//
// Package ed25519 is a migration-period stand-in for the legacy x509 tests, with
// signatures mirroring the removed crypto/ed25519 package. Test-only; see the
// internal/testutil/legacykeys package documentation.
package ed25519

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil/legacykeys"
)

// PrivateKey 是 legacykeys.Key 的别名，对齐原 crypto/ed25519.PrivateKey 的用法。
//
// PrivateKey aliases legacykeys.Key.
type PrivateKey = legacykeys.Key

// PublicKey 是 asym.PublicKey 的别名，对齐原 crypto/ed25519.PublicKey 的用法。
//
// PublicKey aliases asym.PublicKey.
type PublicKey = asym.PublicKey

// GenerateKey 生成一把 Ed25519 私钥（等价原 crypto/ed25519.GenerateKey）。
//
// GenerateKey generates an Ed25519 private key.
func GenerateKey() (*PrivateKey, error) {
	return legacykeys.Wrap(asym.GenerateEd25519())
}
