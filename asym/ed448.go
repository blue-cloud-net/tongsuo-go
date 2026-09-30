package asym

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// ed448SeedSize 是 Ed448 原始私钥种子 / 公钥的字节数（RFC 8032 §5.2）。
// 签名长度为 114 字节。
//
// ed448SeedSize is the byte length of the Ed448 raw private seed and
// public key (RFC 8032 §5.2); Ed448 signatures are 114 bytes.
const ed448SeedSize = 57

// ed448PrivateKey 是 Ed448 私钥的具体类型（非导出）。
//
// ed448PrivateKey is the concrete (unexported) type for Ed448 private keys.
type ed448PrivateKey struct {
	key *core.PKey
}

// ed448PublicKey 是 Ed448 公钥的具体类型（非导出）。
//
// ed448PublicKey is the concrete (unexported) type for Ed448 public keys.
type ed448PublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *ed448PrivateKey) Algorithm() Algorithm { return AlgEd448 }

// Algorithm 实现 Key 接口。
func (k *ed448PublicKey) Algorithm() Algorithm { return AlgEd448 }

// corePKey 实现 Key 接口。
func (k *ed448PrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *ed448PublicKey) corePKey() *core.PKey { return k.key }

// Public 返回配对的公钥（共享底层 core.PKey；Ed448 私钥内部自带派生公钥）。
func (k *ed448PrivateKey) Public() PublicKey {
	return &ed448PublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 导出为 PKCS#8 PEM。
func (k *ed448PrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 导出为 SubjectPublicKeyInfo PEM。
func (k *ed448PublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// GenerateEd448 生成新的 Ed448 签名密钥对（RFC 8032）。
//
// GenerateEd448 generates a fresh Ed448 signing key pair (RFC 8032).
func GenerateEd448() (PrivateKey, error) {
	k, err := core.GenerateED448Key()
	if err != nil {
		return nil, err
	}
	return &ed448PrivateKey{key: k}, nil
}

// SignEd448 使用 Ed448 对 msg 签名，返回 114 字节签名。
// Ed448 采用 RFC 8032 §5.2 的「纯签名」语义：msg 原样参与签名，内部不做任何
// 预哈希；调用方也**不得**预先哈希 msg，否则将破坏与其它实现的互通。
//
// SignEd448 produces a 114-byte Ed448 signature over msg.
//
// Ed448 uses the "pure" signature semantics of RFC 8032 §5.2: msg is
// signed verbatim and no pre-hashing is performed internally. Callers
// must NOT pre-hash msg either, or interop with other implementations
// breaks.
func SignEd448(priv PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: ed448: nil private key")
	}
	if priv.Algorithm() != AlgEd448 {
		return nil, fmt.Errorf("asym: ed448: SignEd448 requires an Ed448 key, got %s", priv.Algorithm())
	}
	return priv.corePKey().SignMessage(msg)
}

// VerifyEd448 使用 Ed448 验签（sig 须为 114 字节）。
// 验签失败返回错误（不返回布尔值）；调用方须将任意非 nil 错误视为认证失败。
//
// VerifyEd448 checks a 114-byte Ed448 signature against msg.
//
// Returns an error (never a boolean) on failure; callers must treat any
// non-nil error as authentication failure.
func VerifyEd448(pub PublicKey, msg, sig []byte) error {
	if pub == nil {
		return fmt.Errorf("asym: ed448: nil public key")
	}
	if pub.Algorithm() != AlgEd448 {
		return fmt.Errorf("asym: ed448: VerifyEd448 requires an Ed448 key, got %s", pub.Algorithm())
	}
	return pub.corePKey().VerifyMessage(msg, sig)
}
