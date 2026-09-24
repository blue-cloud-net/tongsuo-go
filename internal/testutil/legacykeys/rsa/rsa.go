// Package rsa 是 x509 遗留测试的迁移期替身，签名对齐已删除的 crypto/rsa。
//
// 仅测试使用；用法与删除时机见 internal/testutil/legacykeys 的包文档。
//
// Package rsa is a migration-period stand-in for the legacy x509 tests, with
// signatures mirroring the removed crypto/rsa package. Test-only; see the
// internal/testutil/legacykeys package documentation.
package rsa

import (
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil/legacykeys"
)

// PrivateKey 是 legacykeys.Key 的别名，对齐原 crypto/rsa.PrivateKey 的用法。
//
// PrivateKey aliases legacykeys.Key.
type PrivateKey = legacykeys.Key

// PublicKey 是 asym.PublicKey 的别名。
//
// PublicKey aliases asym.PublicKey.
type PublicKey = asym.PublicKey

// GenerateKey 生成一把指定位数的 RSA 私钥（等价原 crypto/rsa.GenerateKey）。
//
// GenerateKey generates an RSA private key of the given bit length.
func GenerateKey(bits int) (*PrivateKey, error) {
	return legacykeys.Wrap(asym.GenerateRSA(bits))
}

// LoadPrivateKeyPEM 从 PEM 加载 RSA 私钥。
//
// LoadPrivateKeyPEM loads an RSA private key from PEM.
func LoadPrivateKeyPEM(pemBytes []byte) (*PrivateKey, error) {
	return legacykeys.LoadPrivateKeyPEM(pemBytes)
}

// LoadPublicKeyPEM 从 PEM 加载 RSA 公钥。
//
// LoadPublicKeyPEM loads an RSA public key from PEM.
func LoadPublicKeyPEM(pemBytes []byte) (PublicKey, error) {
	return legacykeys.LoadPublicKeyPEM(pemBytes)
}
