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
// alg 目前支持 AlgEd25519（seed 须为 32 字节）；Ed448 / X25519 / X448 在
// 对应算法落地后接入同一入口。
// 种子长度不符返回 ErrInvalidSeedLength；alg 不在支持列表返回 ErrUnsupported。
//
// 调用方在调用后须自行清零 seed。
//
// GenerateKeyFromSeed constructs a key pair from a raw private seed.
// alg currently supports AlgEd25519 (seed must be 32 bytes); Ed448 /
// X25519 / X448 will join the same entry point as they land.
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
	default:
		return nil, fmt.Errorf("%w: GenerateKeyFromSeed: %s", ErrUnsupported, alg)
	}
}

// PublicKeyFromBytes 从原始公钥字节构造公钥。
// alg 目前支持 AlgEd25519（raw 须为 32 字节）；X25519 / X448 在对应算法
// 落地后接入同一入口。
// 字节长度不符返回 ErrInvalidPublicKeyLength；alg 不在支持列表返回 ErrUnsupported。
//
// PublicKeyFromBytes constructs a public key from raw public key bytes.
// alg currently supports AlgEd25519 (raw must be 32 bytes); X25519 /
// X448 will join the same entry point as they land.
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
	default:
		return nil, fmt.Errorf("%w: PublicKeyFromBytes: %s", ErrUnsupported, alg)
	}
}

// RawPrivateKey 导出原始私钥字节。
// Ed25519 下为 32 字节种子（RFC 8032 §5.1.2）；其他算法在落地后沿用本入口。
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

// RawPublicKey 导出原始公钥字节（Ed25519 下为 32 字节）。
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

// LoadEd25519PrivateKeyPEM 从 PEM（PKCS#8）加载 Ed25519 私钥。
// 算法标识非 Ed25519 时返回错误。
//
// LoadEd25519PrivateKeyPEM loads an Ed25519 private key from a PKCS#8 PEM
// block. Returns an error when the embedded algorithm is not Ed25519.
func LoadEd25519PrivateKeyPEM(pem []byte) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	if !isEd25519Key(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("asym: ed25519: PEM private key is not Ed25519 (got %s)", alg)
	}
	return &ed25519PrivateKey{key: k}, nil
}

// LoadEd25519PrivateKeyPEMEncrypted 从加密 PEM（"BEGIN ENCRYPTED PRIVATE KEY"）加载 Ed25519 私钥。
// 口令错误或算法非 Ed25519 时返回错误。
//
// LoadEd25519PrivateKeyPEMEncrypted loads an Ed25519 private key from an
// encrypted PEM block (AES-256-CBC + PBKDF2).
func LoadEd25519PrivateKeyPEMEncrypted(pem []byte, pass string) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pem, pass)
	if err != nil {
		return nil, err
	}
	if !isEd25519Key(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("asym: ed25519: encrypted PEM private key is not Ed25519 (got %s)", alg)
	}
	return &ed25519PrivateKey{key: k}, nil
}

// LoadEd25519PublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 Ed25519 公钥。
// 算法非 Ed25519 时返回错误。
//
// LoadEd25519PublicKeyPEM loads an Ed25519 public key from a SPKI PEM block.
func LoadEd25519PublicKeyPEM(pem []byte) (PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	if !isEd25519Key(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("asym: ed25519: PEM public key is not Ed25519 (got %s)", alg)
	}
	return &ed25519PublicKey{key: k}, nil
}

// MarshalEd25519PrivateKeyEncryptedPEM 用口令加密导出 Ed25519 私钥（AES-256-CBC + PBKDF2）。
//
// MarshalEd25519PrivateKeyEncryptedPEM encodes an Ed25519 private key as an
// encrypted PEM block (AES-256-CBC + PBKDF2).
func MarshalEd25519PrivateKeyEncryptedPEM(priv PrivateKey, pass string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: ed25519: nil private key")
	}
	k, ok := priv.(*ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: ed25519: EncryptedPEM requires an Ed25519 key, got %s", priv.Algorithm())
	}
	return k.key.MarshalEncryptedPEM(pass)
}

// MarshalEd25519PrivateKeyEncryptedPEMWithCipher 用指定 cipher 加密导出 Ed25519 私钥。
// cipher 取 OpenSSL 通用名（如 "aes-128-cbc"、"aes-256-cbc"、"des-ede3-cbc"）；
// cipher == "" 与 MarshalEd25519PrivateKeyEncryptedPEM 等价。
func MarshalEd25519PrivateKeyEncryptedPEMWithCipher(priv PrivateKey, cipher, pass string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: ed25519: nil private key")
	}
	k, ok := priv.(*ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: ed25519: EncryptedPEMWithCipher requires an Ed25519 key, got %s", priv.Algorithm())
	}
	return k.key.MarshalEncryptedPEMWithCipher(cipher, pass)
}

// isEd25519Key 报告 *core.PKey 的底层算法是否为 Ed25519。
func isEd25519Key(k *core.PKey) bool {
	return k != nil && k.Algorithm() == "ED25519"
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

// Ed25519Match 判断 priv 的公钥分量是否与 other 相等；nil-safe。
//
// Ed25519Match reports whether the public component of priv equals other's.
func Ed25519Match(priv PrivateKey, other *core.PKey) (bool, error) {
	if priv == nil {
		return false, fmt.Errorf("asym: ed25519: nil private key")
	}
	if priv.Algorithm() != AlgEd25519 {
		return false, fmt.Errorf("asym: ed25519: Ed25519Match requires an Ed25519 key, got %s", priv.Algorithm())
	}
	k := priv.corePKey()
	if k == nil {
		return false, nil
	}
	return k.PublicEqual(other), nil
}
