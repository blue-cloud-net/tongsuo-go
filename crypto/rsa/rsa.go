// Package rsa 基于铜锁原生实现实现 RSA 非对称算法。
//
// 提供密钥生成、PEM 序列化（PKCS#8 / PKCS#1 / 加密）、签名（PKCS#1 v1.5 / PSS）、
// 加解密（PKCS#1 v1.5 / OAEP）与参数提取。签名默认使用 SHA-256 摘要。
package rsa

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PrivateKey 表示 RSA 私钥。
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 RSA 公钥。
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成 bits 位 RSA 密钥对（如 2048）。
func GenerateKey(bits int) (*PrivateKey, error) {
	if bits < 1024 {
		return nil, fmt.Errorf("rsa: key size too small: %d", bits)
	}
	k, err := core.GenerateRSAKey(bits)
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

// LoadPrivateKeyPEM 从 PEM 加载 RSA 私钥（PKCS#8 或 PKCS#1）。
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err == nil {
		return &PrivateKey{key: k}, nil
	}
	k2, err2 := core.LoadPrivateKeyPKCS1PEM(pem)
	if err2 != nil {
		return nil, err
	}
	return &PrivateKey{key: k2}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 RSA 公钥。
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载 RSA 私钥。
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

// MarshalPKCS1PEM 导出私钥为 PKCS#1 PEM（"BEGIN RSA PRIVATE KEY"）。
func (k *PrivateKey) MarshalPKCS1PEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPKCS1PEM()
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

// Params 返回 RSA 参数（N/E 公钥，D/P/Q 私钥）。
func (k *PrivateKey) Params() *core.KeyParams { return k.key.Params() }

// Params 返回 RSA 参数（N/E 公钥）。
func (k *PublicKey) Params() *core.KeyParams { return k.key.Params() }

// SignPKCS1v15 使用 RSA-PKCS#1 v1.5 对 data 签名（SHA-256 摘要）。
func (k *PrivateKey) SignPKCS1v15(data []byte) ([]byte, error) {
	return k.key.SignDigest(data, core.SHA256())
}

// VerifyPKCS1v15 使用 RSA-PKCS#1 v1.5 验签（SHA-256 摘要）。
func (k *PublicKey) VerifyPKCS1v15(data, sig []byte) error {
	return k.key.VerifyDigest(data, sig, core.SHA256())
}

// SignPSS 使用 RSA-PSS 对 data 签名（SHA-256 摘要）。
// saltLen 为盐长字节数；可用 core 包常量（-1=digest 长、-2=auto、-3=max）。
func (k *PrivateKey) SignPSS(data []byte, saltLen int) ([]byte, error) {
	return k.key.SignDigestPSS(data, core.SHA256(), saltLen)
}

// VerifyPSS 使用 RSA-PSS 验签（SHA-256 摘要）。
func (k *PublicKey) VerifyPSS(data, sig []byte, saltLen int) error {
	return k.key.VerifyDigestPSS(data, sig, core.SHA256(), saltLen)
}

// EncryptPKCS1v15 使用 RSA-PKCS#1 v1.5 填充加密（明文须短于模数）。
func EncryptPKCS1v15(pub *PublicKey, data []byte) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("rsa: nil public key")
	}
	return pub.key.EncryptPKCS1v15(data)
}

// DecryptPKCS1v15 使用 RSA-PKCS#1 v1.5 填充解密。
func DecryptPKCS1v15(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("rsa: nil private key")
	}
	return priv.key.DecryptPKCS1v15(data)
}

// EncryptOAEP 使用 RSA-OAEP 填充加密。md 为 OAEP/MGF1 摘要（nil 时用 SHA-256）。
func EncryptOAEP(pub *PublicKey, data []byte, md *core.Digest) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("rsa: nil public key")
	}
	if md == nil {
		md = core.SHA256()
	}
	return pub.key.EncryptOAEP(data, md)
}

// DecryptOAEP 使用 RSA-OAEP 填充解密。md 须与加密时一致。
func DecryptOAEP(priv *PrivateKey, data []byte, md *core.Digest) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("rsa: nil private key")
	}
	if md == nil {
		md = core.SHA256()
	}
	return priv.key.DecryptOAEP(data, md)
}

// Match 判断私钥与另一密钥（公钥/私钥/证书公钥）是否匹配。
func (k *PrivateKey) Match(other *core.PKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(other)
}
