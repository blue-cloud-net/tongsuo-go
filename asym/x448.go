package asym

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// x448KeySize 是 X448 原始私钥 / 公钥的字节数（RFC 7748 §5）。
//
// x448KeySize is the byte length of an X448 raw private key and public
// key (RFC 7748 §5).
const x448KeySize = 56

// x448PrivateKey 是 X448 私钥的具体类型（非导出）。
//
// x448PrivateKey is the concrete (unexported) type for X448 private keys.
type x448PrivateKey struct {
	key *core.PKey
}

// x448PublicKey 是 X448 公钥的具体类型（非导出）。
//
// x448PublicKey is the concrete (unexported) type for X448 public keys.
type x448PublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *x448PrivateKey) Algorithm() Algorithm { return AlgX448 }

// Algorithm 实现 Key 接口。
func (k *x448PublicKey) Algorithm() Algorithm { return AlgX448 }

// corePKey 实现 Key 接口。
func (k *x448PrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *x448PublicKey) corePKey() *core.PKey { return k.key }

// Public 返回配对的公钥（共享底层 core.PKey）。
func (k *x448PrivateKey) Public() PublicKey {
	return &x448PublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 导出为 PKCS#8 PEM。
func (k *x448PrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 导出为 SubjectPublicKeyInfo PEM。
func (k *x448PublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// GenerateX448 生成新的 X448 密钥对（RFC 7748）。
//
// X448 是**密钥协商**算法，不具备签名 / 加解密能力：本包只提供生成与
// 编解码入口，协商运算见 ecdh 包的 SharedSecret。
//
// GenerateX448 generates a fresh X448 key pair (RFC 7748).
//
// X448 is a **key-agreement** algorithm and offers neither signing nor
// encryption: this package only provides generation and encoding entry
// points, while the agreement operation lives in the ecdh package's
// SharedSecret.
func GenerateX448() (PrivateKey, error) {
	k, err := core.GenerateX448Key()
	if err != nil {
		return nil, err
	}
	return &x448PrivateKey{key: k}, nil
}
