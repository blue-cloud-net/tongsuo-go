// Package ed448 是 x509 遗留测试的迁移期替身，签名对齐已删除的 crypto/ed448。
//
// 仅测试使用；用法与删除时机见 internal/testutil/legacykeys 的包文档。
//
// Package ed448 is a migration-period stand-in for the legacy x509 tests, with
// signatures mirroring the removed crypto/ed448 package. Test-only; see the
// internal/testutil/legacykeys package documentation.
package ed448

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil/legacykeys"
)

// PrivateKey 是 legacykeys.Key 的别名，对齐原 crypto/ed448.PrivateKey 的用法。
//
// PrivateKey aliases legacykeys.Key.
type PrivateKey = legacykeys.Key

// PublicKey 是 asym.PublicKey 的别名。
//
// PublicKey aliases asym.PublicKey.
type PublicKey = asym.PublicKey

// GenerateKey 生成一把 Ed448 私钥（等价原 crypto/ed448.GenerateKey）。
//
// GenerateKey generates an Ed448 private key.
func GenerateKey() (*PrivateKey, error) {
	return legacykeys.Wrap(asym.GenerateEd448())
}
