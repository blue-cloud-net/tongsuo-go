// Package sm2 基于铜锁原生实现实现 GB/T 32918 SM2 非对称算法。
//
// 提供密钥生成、PEM 序列化、加密/解密、签名/验签（SM2withSM3）。
// 签名与密文均为 ASN.1 DER 格式，与铜锁 openssl 输出一致。
package sm2

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// DefaultID 为 SM2 默认用户标识（GM/T 0003-2012）。
var DefaultID = []byte("1234567812345678")

// PrivateKey 表示 SM2 私钥。
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 SM2 公钥。
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成新的 SM2 密钥对。
func GenerateKey() (*PrivateKey, error) {
	k, err := core.GenerateSM2Key()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// Key 返回底层核心密钥对象（供内部跨包使用，如 crypto/x509）。
func (k *PrivateKey) Key() *core.PKey { return k.key }

// Key 返回底层核心密钥对象（供内部跨包使用，如 crypto/x509）。
func (k *PublicKey) Key() *core.PKey { return k.key }

// PublicKeyFromPKey 用底层核心密钥构造 PublicKey（供内部跨包使用，如 crypto/x509）。
func PublicKeyFromPKey(k *core.PKey) *PublicKey { return &PublicKey{key: k} }

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 SM2 私钥。
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 SM2 公钥。
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// Public 返回对应的公钥（引用同一底层密钥）。
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{key: k.key}
}

// MarshalPEM 导出公钥为 PEM（SubjectPublicKeyInfo）。
func (k *PublicKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// Encrypt 使用 SM2 公钥加密 data。
// 输出为 Tongsuo 8.x（OpenSSL 3.x）的 ASN.1 DER 格式（内含 C1C3C2），与
// `openssl pkeyutl -encrypt` 一致。
func Encrypt(pub *PublicKey, data []byte) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("sm2: nil public key")
	}
	return pub.key.Encrypt(data)
}

// Decrypt 使用 SM2 私钥解密。
func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("sm2: nil private key")
	}
	return priv.key.Decrypt(data)
}

// Sign 使用 SM2withSM3 对 data 签名，返回 ASN.1 DER 签名。
func Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	return SignWithID(priv, data, nil)
}

// Verify 使用 SM2withSM3 验签。
func Verify(pub *PublicKey, data, sig []byte) error {
	return VerifyWithID(pub, data, sig, nil)
}

// SignWithID 使用自定义 userId 对 data 签名。
func SignWithID(priv *PrivateKey, data, id []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("sm2: nil private key")
	}
	return priv.key.Sign(data, id)
}

// VerifyWithID 使用自定义 userId 验签。
func VerifyWithID(pub *PublicKey, data, sig, id []byte) error {
	if pub == nil || pub.key == nil {
		return fmt.Errorf("sm2: nil public key")
	}
	return pub.key.Verify(data, sig, id)
}
