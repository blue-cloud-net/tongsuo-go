// Package ecdsa 基于铜锁原生实现实现 ECDSA 非对称算法。
//
// 提供密钥生成、PEM 序列化、签名 / 验签（ECDSA-SHA256，ASN.1 DER）与参数提取。
package ecdsa

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PrivateKey 表示 ECDSA 私钥。
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 ECDSA 公钥。
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成指定曲线的 EC 密钥对（curve 如 "prime256v1"、"secp384r1"、"sm2"）。
func GenerateKey(curve string) (*PrivateKey, error) {
	if curve == "" {
		return nil, fmt.Errorf("ecdsa: empty curve name")
	}
	k, err := core.GenerateECKey(curve)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// Key 返回底层核心密钥对象（供内部跨包使用，如 crypto/x509）。
func (k *PrivateKey) Key() *core.PKey { return k.key }

// Key 返回底层核心密钥对象（供内部跨包使用，如 crypto/x509）。
func (k *PublicKey) Key() *core.PKey { return k.key }

// Public 返回对应的公钥（引用同一底层密钥）。
func (k *PrivateKey) Public() *PublicKey { return &PublicKey{key: k.key} }

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 ECDSA 私钥。
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 ECDSA 公钥。
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载 ECDSA 私钥。
func LoadEncryptedPEM(pem []byte, pass string) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pem, pass)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalEncryptedPEM 用口令加密导出私钥为 PEM（AES-256-CBC）。
func (k *PrivateKey) MarshalEncryptedPEM(pass string) ([]byte, error) {
	return k.key.MarshalEncryptedPEM(pass)
}

// MarshalPEM 导出公钥为 PEM（SubjectPublicKeyInfo）。
func (k *PublicKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// ChangePassword 读取旧口令加密的 PEM 并导出为新口令加密。
func ChangePassword(pemBytes []byte, oldPass, newPass string) ([]byte, error) {
	return core.ChangePrivateKeyPassword(pemBytes, oldPass, newPass)
}

// Params 返回 EC 参数（Curve / X / Y 公钥点，D 私钥标量）。
func (k *PrivateKey) Params() *core.KeyParams { return k.key.Params() }

// Params 返回 EC 参数（Curve / X / Y 公钥点）。
func (k *PublicKey) Params() *core.KeyParams { return k.key.Params() }

// Sign 使用 ECDSA-SHA256 对 data 签名，返回 ASN.1 DER 签名。
func Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("ecdsa: nil private key")
	}
	return priv.key.SignDigest(data, core.SHA256())
}

// Verify 使用 ECDSA-SHA256 验签（签名须为 ASN.1 DER）。
func Verify(pub *PublicKey, data, sig []byte) error {
	if pub == nil || pub.key == nil {
		return fmt.Errorf("ecdsa: nil public key")
	}
	return pub.key.VerifyDigest(data, sig, core.SHA256())
}

// Match 判断私钥与另一密钥（公钥/私钥/证书公钥）是否匹配。
func (k *PrivateKey) Match(other *core.PKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(other)
}
