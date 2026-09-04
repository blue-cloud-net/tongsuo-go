// Package ed25519 基于铜锁原生实现封装 Ed25519 签名算法（RFC 8032）。
// 提供密钥生成、PEM（PKCS#8 / SPKI）序列化、纯签名 / 验签，以及
// 32 字节原始私钥种子（seed）和公钥字节互操作。
//
// 摘要方面 Ed25519 走"纯签名"：调用方传入的 msg 即被签内容，不在内部再做
// SHA-256 / SHA-512 等预哈希——这与 RFC 8032 的算法定义一致。
//
// Package ed25519 wraps the Tongsuo-native Ed25519 signature algorithm
// (RFC 8032). It exposes key generation, PEM (de)serialization for
// PKCS#8 private keys and SubjectPublicKeyInfo public keys, pure
// sign / verify (no internal pre-hashing), and a 32-byte raw private-
// seed / public-key byte interop.
//
// Ed25519 signs messages directly without any digest pre-processing; the
// algorithm defined in RFC 8032 absorbs the message bytes verbatim, and
// callers must NOT pre-hash the input (this would break interop with other
// Ed25519 implementations).
package ed25519

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// seedSize 是 Ed25519 原始私钥种子（RFC 8032 §5.1.2）的字节数。
//
// seedSize is the raw private-seed byte length of Ed25519 (RFC 8032 §5.1.2).
const seedSize = 32

// ErrInvalidSeedLength 表示传入的原始私钥种子长度不是 Ed25519 规定的 32 字节。
//
// ErrInvalidSeedLength reports that a supplied raw private seed does not
// have the 32-byte length mandated by Ed25519.
var ErrInvalidSeedLength = fmt.Errorf("ed25519: invalid seed length, want %d bytes", seedSize)

// ErrInvalidPublicKeyLength 表示传入的原始公钥字节长度不是 Ed25519 规定的 32 字节。
//
// ErrInvalidPublicKeyLength reports that a supplied raw public key does
// not have the 32-byte length mandated by Ed25519.
var ErrInvalidPublicKeyLength = fmt.Errorf("ed25519: invalid public key length, want %d bytes", seedSize)

// PrivateKey 表示 Ed25519 私钥，底层持有 *core.PKey 句柄。
//
// PrivateKey is an Ed25519 private key backed by an internal *core.PKey.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 Ed25519 公钥，底层持有 *core.PKey 句柄。
//
// PublicKey is an Ed25519 public key backed by an internal *core.PKey.
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成新的 Ed25519 签名密钥对。
//
// 底层失败时返回包装 OpError 的错误。
//
// GenerateKey generates a fresh Ed25519 signing key pair.
//
// On failure it returns an error wrapping an OpError.
func GenerateKey() (*PrivateKey, error) {
	k, err := core.GenerateED25519Key()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// PrivateKeyFromSeed 从 32 字节种子构造私钥（种子来自 RNG 或外部熵源）。
//
// seed 长度必须为 32 字节；其他长度返回 ErrInvalidSeedLength。
// 调用方在调用后须自行清零 seed。
//
// PrivateKeyFromSeed constructs an Ed25519 private key from a 32-byte
// raw private seed.
//
// seed must be exactly 32 bytes; other lengths return ErrInvalidSeedLength.
// The caller is responsible for zeroising seed after the call.
func PrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != seedSize {
		return nil, ErrInvalidSeedLength
	}
	k, err := core.NewRawPrivateKey(native.EvpPkeyED25519, seed)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// PublicKeyFromBytes 从 32 字节公钥字节构造公钥。
//
// raw 长度必须为 32 字节；其他长度返回 ErrInvalidPublicKeyLength。
//
// PublicKeyFromBytes constructs an Ed25519 public key from 32 raw bytes.
//
// raw must be exactly 32 bytes; other lengths return ErrInvalidPublicKeyLength.
func PublicKeyFromBytes(raw []byte) (*PublicKey, error) {
	if len(raw) != seedSize {
		return nil, ErrInvalidPublicKeyLength
	}
	k, err := core.NewRawPublicKey(native.EvpPkeyED25519, raw)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
//
// Key returns the underlying *core.PKey. It is intended for internal
// cross-package use (for example x509 certificate building) and is not
// part of the stable public API.
func (k *PrivateKey) Key() *core.PKey { return k.key }

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
//
// Key returns the underlying *core.PKey. It is intended for internal
// cross-package use (for example x509 certificate building) and is not
// part of the stable public API.
func (k *PublicKey) Key() *core.PKey { return k.key }

// Public 返回对应的公钥（引用同一底层密钥）；返回的 *PublicKey 包装同一个底层 *core.PKey，
// 对一侧执行的密码学操作在另一侧也可观察到（Ed25519 私钥本身即携带派生公钥）。
//
// Public returns the public key associated with this private key; the
// returned *PublicKey wraps the same underlying *core.PKey and any
// cryptographic operation on one side is observable on the other
// (Ed25519 private keys carry the derived public key internally).
func (k *PrivateKey) Public() (*PublicKey, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ed25519: nil private key")
	}
	return &PublicKey{key: k.key}, nil
}

// Seed 导出 32 字节原始私钥种子。
//
// 失败时返回包装 OpError 的错误；调用方须自行清零返回的字节。
//
// Seed exports the 32-byte raw private seed.
//
// On failure it returns an error wrapping an OpError; the caller is
// responsible for zeroising the returned bytes.
func (k *PrivateKey) Seed() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ed25519: nil private key")
	}
	return k.key.RawPrivateKey()
}

// Bytes 导出 32 字节公钥字节。
//
// 失败时返回包装 OpError 的错误；返回的字节不敏感，不需要清零。
//
// Bytes exports the 32-byte raw public key bytes.
//
// On failure it returns an error wrapping an OpError; the returned bytes
// are not sensitive and need not be zeroised.
func (k *PublicKey) Bytes() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ed25519: nil public key")
	}
	return k.key.RawPublicKey()
}

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 Ed25519 私钥。
//
// 解析 PKCS#8（"-----BEGIN PRIVATE KEY-----"）PEM 块；底层走 EVP 通用路径，
// 自动识别 Ed25519 算法。失败时返回包装 OpError 的错误。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying a PKCS#8
// ("-----BEGIN PRIVATE KEY-----") Ed25519 private key. The Tongsuo EVP
// pipeline auto-detects the Ed25519 algorithm. On failure it returns an
// error wrapping an OpError.
func LoadPrivateKeyPEM(pemBytes []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 Ed25519 公钥。
//
// 解析 SPKI（"-----BEGIN PUBLIC KEY-----"）PEM 块；底层走 EVP 通用路径。
// 失败时返回包装 OpError 的错误。
//
// LoadPublicKeyPEM parses an unencrypted PEM block carrying a
// SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") Ed25519 public key.
// The Tongsuo EVP pipeline auto-detects the Ed25519 algorithm. On failure
// it returns an error wrapping an OpError.
func LoadPublicKeyPEM(pemBytes []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载 Ed25519 私钥。
//
// 解析加密 PEM 块（AES-256-CBC + PBKDF2 派生密钥，
// "-----BEGIN ENCRYPTED PRIVATE KEY-----"），使用给定口令；空口令或任意
// 解密错误返回错误。
//
// LoadEncryptedPEM parses an encrypted PEM block
// ("-----BEGIN ENCRYPTED PRIVATE KEY-----") using the given passphrase
// and returns the underlying Ed25519 private key. An empty passphrase or
// any decryption error returns an error.
func LoadEncryptedPEM(pemBytes []byte, pass string) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pemBytes, pass)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
//
// 以 PKCS#8 PEM 块（"-----BEGIN PRIVATE KEY-----"）编码私钥；失败时返回
// 包装 OpError 的错误。
//
// MarshalPEM encodes the private key as a PKCS#8 PEM block
// ("-----BEGIN PRIVATE KEY-----"). On failure it returns an error
// wrapping an OpError.
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ed25519: nil private key")
	}
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalEncryptedPEM 用口令加密导出私钥为 PEM（AES-256-CBC）。
//
// 以加密 PEM 块（"-----BEGIN ENCRYPTED PRIVATE KEY-----"）编码私钥，
// 口令作为 AES-256-CBC + PBKDF2 密钥派生基础；空口令或任意底层失败返回错误。
//
// MarshalEncryptedPEM encodes the private key as an encrypted PEM block
// ("-----BEGIN ENCRYPTED PRIVATE KEY-----") using the given passphrase
// as the basis for an AES-256-CBC + PBKDF2 key. An empty passphrase or
// any underlying failure returns an error.
func (k *PrivateKey) MarshalEncryptedPEM(pass string) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ed25519: nil private key")
	}
	return k.key.MarshalEncryptedPEM(pass)
}

// MarshalPEM 导出公钥为 PEM（SubjectPublicKeyInfo）。
//
// 以 SubjectPublicKeyInfo PEM 块（"-----BEGIN PUBLIC KEY-----"）编码公钥；
// 失败时返回包装 OpError 的错误。
//
// MarshalPEM encodes the public key as a SubjectPublicKeyInfo PEM block
// ("-----BEGIN PUBLIC KEY-----"). On failure it returns an error
// wrapping an OpError.
func (k *PublicKey) MarshalPEM() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ed25519: nil public key")
	}
	return k.key.MarshalPublicKeyPEM()
}

// ChangePassword 读取旧口令加密的 PEM 并导出为新口令加密；oldPass 解密失败或重加密失败时返回错误。
//
// ChangePassword reads an encrypted private-key PEM, decrypts it with
// oldPass, and returns a freshly encrypted PEM under newPass. It returns
// an error when oldPass fails to decrypt the input or when re-encryption
// fails.
func ChangePassword(pemBytes []byte, oldPass, newPass string) ([]byte, error) {
	return core.ChangePrivateKeyPassword(pemBytes, oldPass, newPass)
}

// Sign 使用 Ed25519 对 msg 签名，返回 64 字节签名。
//
// msg 即被签内容；Ed25519 走 RFC 8032 定义的"纯签名"语义，调用方传入的 msg
// 不会被本函数再次预哈希（这也意味着调用方**不应**对 msg 做预哈希，否则会
//与其它 Ed25519 实现互不兼容）。priv 为 nil 或底层为 nil 时返回错误；
//底层签名失败返回包装 OpError 的错误。
//
// Sign produces an Ed25519 signature over msg and returns 64 bytes.
//
// Ed25519 uses the "pure" signature semantics defined in RFC 8032; the
// supplied msg bytes are signed verbatim and this function does NOT pre-
// hash them (callers MUST NOT pre-hash msg either, or interop with other
// Ed25519 implementations breaks). priv or priv.key nil returns an
// error; underlying sign failure returns a wrapped OpError.
func Sign(priv *PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("ed25519: nil private key")
	}
	return priv.key.SignMessage(msg)
}

// Verify 使用 Ed25519 验签（sig 须为 64 字节 Ed25519 签名）。
//
// pub 为 nil、底层为 nil 或签名长度/格式错误时返回错误（永不返回 bool）。
// 调用方应将任意非 nil 错误视为认证失败，无需进一步区分原因。
//
// Verify validates an Ed25519 signature sig (must be 64 bytes) against msg.
//
// Returns an error (never a boolean) when pub is nil, the signature length
// or format is wrong, or the verification fails. Callers should treat
// any non-nil error as authentication failure without inspecting it.
func Verify(pub *PublicKey, msg, sig []byte) error {
	if pub == nil || pub.key == nil {
		return fmt.Errorf("ed25519: nil public key")
	}
	return pub.key.VerifyMessage(msg, sig)
}

// Match 判断私钥与另一密钥（公钥/私钥/证书公钥）是否匹配；k 为 nil 或底层为 nil 时返回 false。
//
// 仅比较公钥分量（SPKI DER）；私钥与其内嵌的公钥天然匹配。供 x509 等跨包配对
// 使用，不属于稳定公共 API。
//
// Match reports whether the public component of this private key equals
// the public component of other (which may be a private key, public key,
// or certificate public key). Returns false when k or k.key is nil.
// It compares only the public SPKI DER (a private key matches its
// embedded public key). Intended for cross-package use (e.g. x509
// certificate / key pairing) and not part of the stable public API.
func (k *PrivateKey) Match(other *core.PKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(other)
}