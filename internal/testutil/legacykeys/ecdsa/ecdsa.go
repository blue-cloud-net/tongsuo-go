// Package ecdsa 是 x509 遗留测试的迁移期替身，签名对齐已删除的 crypto/ecdsa。
//
// 仅测试使用；用法与删除时机见 internal/testutil/legacykeys 的包文档。
//
// Package ecdsa is a migration-period stand-in for the legacy x509 tests, with
// signatures mirroring the removed crypto/ecdsa package. Test-only; see the
// internal/testutil/legacykeys package documentation.
package ecdsa

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil/legacykeys"
)

// PrivateKey 是 legacykeys.Key 的别名，对齐原 crypto/ecdsa.PrivateKey 的用法。
//
// PrivateKey aliases legacykeys.Key.
type PrivateKey = legacykeys.Key

// PublicKey 是 asym.PublicKey 的别名。
//
// PublicKey aliases asym.PublicKey.
type PublicKey = asym.PublicKey

// curveAliases 把遗留测试里使用的 openssl 风格曲线名映射到 asym 常量。
//
// curveAliases maps the openssl-style curve names used by the legacy tests onto
// the asym constants.
var curveAliases = map[string]string{
	"prime256v1": asym.CurveP256,
	"secp256r1":  asym.CurveP256,
	"p-256":      asym.CurveP256,
	"secp384r1":  asym.CurveP384,
	"p-384":      asym.CurveP384,
	"secp521r1":  asym.CurveP521,
	"p-521":      asym.CurveP521,
	"secp256k1":  asym.CurveSecp256k1,
}

// GenerateKey 在指定曲线上生成 EC/ECDSA 私钥（等价原 crypto/ecdsa.GenerateKey）。
// curve 接受 openssl 风格名（如 "prime256v1"）或 asym.Curve* 常量。
//
// GenerateKey generates an EC/ECDSA private key on the named curve.
func GenerateKey(curve string) (*PrivateKey, error) {
	name, ok := curveAliases[toLower(curve)]
	if !ok {
		name = curve
	}
	return legacykeys.Wrap(asym.GenerateEC(name))
}

// toLower 是小写化的最小实现，避免为测试替身引入额外依赖。
//
// toLower is a minimal lower-casing helper.
func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// LoadPrivateKeyPEM 从 PEM 加载 EC/ECDSA 私钥。
//
// LoadPrivateKeyPEM loads an EC/ECDSA private key from PEM.
func LoadPrivateKeyPEM(pemBytes []byte) (*PrivateKey, error) {
	return legacykeys.LoadPrivateKeyPEM(pemBytes)
}
