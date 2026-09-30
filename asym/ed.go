package asym

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// ed25519SeedSize 是 Ed25519 原始私钥种子 / 公钥的字节数（RFC 8032 §5.1.2）。
//
// ed25519SeedSize is the byte length of the Ed25519 raw private seed and
// public key (RFC 8032 §5.1.2).
const ed25519SeedSize = 32

// ed25519PrivateKey 是 Ed25519 私钥的具体类型（非导出）。
//
// ed25519PrivateKey is the concrete (unexported) type for Ed25519 private keys.
type ed25519PrivateKey struct {
	key *core.PKey
}

// ed25519PublicKey 是 Ed25519 公钥的具体类型（非导出）。
//
// ed25519PublicKey is the concrete (unexported) type for Ed25519 public keys.
type ed25519PublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *ed25519PrivateKey) Algorithm() Algorithm { return AlgEd25519 }

// Algorithm 实现 Key 接口。
func (k *ed25519PublicKey) Algorithm() Algorithm { return AlgEd25519 }

// corePKey 实现 Key 接口。
func (k *ed25519PrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *ed25519PublicKey) corePKey() *core.PKey { return k.key }

// Public 返回配对的公钥（共享底层 core.PKey；Ed25519 私钥内部自带派生公钥）。
func (k *ed25519PrivateKey) Public() PublicKey {
	return &ed25519PublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 导出为 PKCS#8 PEM。
func (k *ed25519PrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPublicKeyPEM 导出为 SubjectPublicKeyInfo PEM。
func (k *ed25519PublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// GenerateEd25519 生成新的 Ed25519 签名密钥对（RFC 8032）。
//
// GenerateEd25519 generates a fresh Ed25519 signing key pair (RFC 8032).
func GenerateEd25519() (PrivateKey, error) {
	k, err := core.GenerateED25519Key()
	if err != nil {
		return nil, err
	}
	return &ed25519PrivateKey{key: k}, nil
}

// GenerateKeyFromSeed 从原始私钥种子构造密钥对。
// alg 支持 AlgEd25519（32 字节）、AlgEd448（57 字节）、AlgX25519（32 字节）
// 与 AlgX448（56 字节）。
// 种子长度不符返回 ErrInvalidSeedLength；alg 不在支持列表返回 ErrUnsupported。
//
// 调用方在调用后须自行清零 seed。
//
// GenerateKeyFromSeed constructs a key pair from a raw private seed.
// alg supports AlgEd25519 (32 bytes), AlgEd448 (57 bytes), AlgX25519
// (32 bytes) and AlgX448 (56 bytes).
//
// A wrong seed length returns ErrInvalidSeedLength and an unsupported
// alg returns ErrUnsupported. The caller is responsible for zeroising
// seed after the call.
func GenerateKeyFromSeed(alg Algorithm, seed []byte) (PrivateKey, error) {
	switch alg {
	case AlgEd25519:
		if len(seed) != ed25519SeedSize {
			return nil, fmt.Errorf("%w: ed25519: got %d, want %d", ErrInvalidSeedLength, len(seed), ed25519SeedSize)
		}
		k, err := core.NewRawPrivateKey(core.PKeyAlgoED25519, seed)
		if err != nil {
			return nil, err
		}
		return &ed25519PrivateKey{key: k}, nil
	case AlgEd448:
		if len(seed) != ed448SeedSize {
			return nil, fmt.Errorf("%w: ed448: got %d, want %d", ErrInvalidSeedLength, len(seed), ed448SeedSize)
		}
		k, err := core.NewRawPrivateKey(core.PKeyAlgoED448, seed)
		if err != nil {
			return nil, err
		}
		return &ed448PrivateKey{key: k}, nil
	case AlgX25519:
		if len(seed) != x25519KeySize {
			return nil, fmt.Errorf("%w: x25519: got %d, want %d", ErrInvalidSeedLength, len(seed), x25519KeySize)
		}
		k, err := core.NewRawPrivateKey(core.PKeyAlgoX25519, seed)
		if err != nil {
			return nil, err
		}
		return &x25519PrivateKey{key: k}, nil
	case AlgX448:
		if len(seed) != x448KeySize {
			return nil, fmt.Errorf("%w: x448: got %d, want %d", ErrInvalidSeedLength, len(seed), x448KeySize)
		}
		k, err := core.NewRawPrivateKey(core.PKeyAlgoX448, seed)
		if err != nil {
			return nil, err
		}
		return &x448PrivateKey{key: k}, nil
	default:
		return nil, fmt.Errorf("%w: GenerateKeyFromSeed: %s", ErrUnsupported, alg)
	}
}

// PublicKeyFromBytes 从原始公钥字节构造公钥。
// alg 支持 AlgEd25519（32 字节）、AlgEd448（57 字节）、AlgX25519（32 字节）
// 与 AlgX448（56 字节）。
// 字节长度不符返回 ErrInvalidPublicKeyLength；alg 不在支持列表返回 ErrUnsupported。
//
// PublicKeyFromBytes constructs a public key from raw public key bytes.
// alg supports AlgEd25519 (32 bytes), AlgEd448 (57 bytes), AlgX25519
// (32 bytes) and AlgX448 (56 bytes).
//
// A wrong length returns ErrInvalidPublicKeyLength and an unsupported alg
// returns ErrUnsupported.
func PublicKeyFromBytes(alg Algorithm, raw []byte) (PublicKey, error) {
	switch alg {
	case AlgEd25519:
		if len(raw) != ed25519SeedSize {
			return nil, fmt.Errorf("%w: ed25519: got %d, want %d", ErrInvalidPublicKeyLength, len(raw), ed25519SeedSize)
		}
		k, err := core.NewRawPublicKey(core.PKeyAlgoED25519, raw)
		if err != nil {
			return nil, err
		}
		return &ed25519PublicKey{key: k}, nil
	case AlgEd448:
		if len(raw) != ed448SeedSize {
			return nil, fmt.Errorf("%w: ed448: got %d, want %d", ErrInvalidPublicKeyLength, len(raw), ed448SeedSize)
		}
		k, err := core.NewRawPublicKey(core.PKeyAlgoED448, raw)
		if err != nil {
			return nil, err
		}
		return &ed448PublicKey{key: k}, nil
	case AlgX25519:
		if len(raw) != x25519KeySize {
			return nil, fmt.Errorf("%w: x25519: got %d, want %d", ErrInvalidPublicKeyLength, len(raw), x25519KeySize)
		}
		k, err := core.NewRawPublicKey(core.PKeyAlgoX25519, raw)
		if err != nil {
			return nil, err
		}
		return &x25519PublicKey{key: k}, nil
	case AlgX448:
		if len(raw) != x448KeySize {
			return nil, fmt.Errorf("%w: x448: got %d, want %d", ErrInvalidPublicKeyLength, len(raw), x448KeySize)
		}
		k, err := core.NewRawPublicKey(core.PKeyAlgoX448, raw)
		if err != nil {
			return nil, err
		}
		return &x448PublicKey{key: k}, nil
	default:
		return nil, fmt.Errorf("%w: PublicKeyFromBytes: %s", ErrUnsupported, alg)
	}
}

// RawPrivateKey 导出原始私钥字节。
// Ed25519 下为 32 字节种子、Ed448 下为 57 字节种子（RFC 8032 §5.1.2 / §5.2）；
// 其他算法在落地后沿用本入口。
//
// 调用方须自行清零返回的字节。
//
// RawPrivateKey exports the raw private key bytes. For Ed25519 this is
// the 32-byte seed (RFC 8032 §5.1.2); other algorithms reuse this entry
// point as they land.
//
// The caller is responsible for zeroising the returned bytes.
func RawPrivateKey(priv PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: nil private key")
	}
	return priv.corePKey().RawPrivateKey()
}

// RawPublicKey 导出原始公钥字节（Ed25519 为 32 字节、Ed448 为 57 字节）。
// 返回的字节不敏感，无需清零。
//
// RawPublicKey exports the raw public key bytes (32 bytes for Ed25519).
// The returned bytes are not sensitive and need not be zeroised.
func RawPublicKey(pub PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("asym: nil public key")
	}
	return pub.corePKey().RawPublicKey()
}

// SignEd25519 使用 Ed25519 对 msg 签名，返回 64 字节签名。
// Ed25519 采用 RFC 8032 的「纯签名」语义：msg 原样参与签名，内部不做任何
// 预哈希；调用方也**不得**预先哈希 msg，否则将破坏与其它实现的互通。
//
// SignEd25519 produces a 64-byte Ed25519 signature over msg.
//
// Ed25519 uses the "pure" signature semantics of RFC 8032: msg is signed
// verbatim and no pre-hashing is performed internally. Callers must NOT
// pre-hash msg either, or interop with other implementations breaks.
func SignEd25519(priv PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: ed25519: nil private key")
	}
	if priv.Algorithm() != AlgEd25519 {
		return nil, fmt.Errorf("asym: ed25519: SignEd25519 requires an Ed25519 key, got %s", priv.Algorithm())
	}
	return priv.corePKey().SignMessage(msg)
}

// VerifyEd25519 使用 Ed25519 验签（sig 须为 64 字节）。
// 验签失败返回错误（不返回布尔值）；调用方须将任意非 nil 错误视为认证失败。
//
// VerifyEd25519 checks a 64-byte Ed25519 signature against msg.
//
// Returns an error (never a boolean) on failure; callers must treat any
// non-nil error as authentication failure.
func VerifyEd25519(pub PublicKey, msg, sig []byte) error {
	if pub == nil {
		return fmt.Errorf("asym: ed25519: nil public key")
	}
	if pub.Algorithm() != AlgEd25519 {
		return fmt.Errorf("asym: ed25519: VerifyEd25519 requires an Ed25519 key, got %s", pub.Algorithm())
	}
	return pub.corePKey().VerifyMessage(msg, sig)
}
