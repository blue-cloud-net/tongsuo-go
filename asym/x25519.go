package asym

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// x25519KeySize 是 X25519 原始私钥 / 公钥的字节数（RFC 7748 §5）。
//
// x25519KeySize is the byte length of an X25519 raw private key and
// public key (RFC 7748 §5).
const x25519KeySize = 32

// x25519PrivateKey 是 X25519 私钥的具体类型（非导出）。
//
// x25519PrivateKey is the concrete (unexported) type for X25519 private keys.
type x25519PrivateKey struct {
	key *core.PKey
}

// x25519PublicKey 是 X25519 公钥的具体类型（非导出）。
//
// x25519PublicKey is the concrete (unexported) type for X25519 public keys.
type x25519PublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *x25519PrivateKey) Algorithm() Algorithm { return AlgX25519 }

// Algorithm 实现 Key 接口。
func (k *x25519PublicKey) Algorithm() Algorithm { return AlgX25519 }

// corePKey 实现 Key 接口。
func (k *x25519PrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *x25519PublicKey) corePKey() *core.PKey { return k.key }

// Public 返回配对的公钥（共享底层 core.PKey）。
func (k *x25519PrivateKey) Public() PublicKey {
	return &x25519PublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 导出为 PKCS#8 PEM。
func (k *x25519PrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 导出为 SubjectPublicKeyInfo PEM。
func (k *x25519PublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// GenerateX25519 生成新的 X25519 密钥对（RFC 7748）。
//
// X25519 是**密钥协商**算法，不具备签名 / 加解密能力：本包只提供生成与
// 编解码入口，协商运算见 ecdh 包的 SharedSecret。
//
// GenerateX25519 generates a fresh X25519 key pair (RFC 7748).
//
// X25519 is a **key-agreement** algorithm and offers neither signing nor
// encryption: this package only provides generation and encoding entry
// points, while the agreement operation lives in the ecdh package's
// SharedSecret.
func GenerateX25519() (PrivateKey, error) {
	k, err := core.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	return &x25519PrivateKey{key: k}, nil
}
