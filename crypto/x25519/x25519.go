// Package x25519 基于铜锁原生实现封装 X25519 ECDH 密钥交换（RFC 7748）。
// 提供密钥生成、PEM（PKCS#8 / SPKI）序列化、共享密钥计算 SharedSecret，
// 以及 32 字节原始私钥 / 公钥字节互操作（与 Go 标准库 crypto/ecdh、
// WireGuard 等可直接对接）。
//
// Package x25519 wraps the Tongsuo-native X25519 ECDH key-agreement
// algorithm (RFC 7748). It exposes key generation, PEM
// (de)serialization for PKCS#8 private keys and SubjectPublicKeyInfo
// public keys, shared-secret computation (SharedSecret), and a 32-byte
// raw private/public byte interop (compatible with Go's standard
// crypto/ecdh and WireGuard).
package x25519

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// keySize 是 X25519 原始私钥 / 公钥字节数（RFC 7748 §5）。
//
// keySize is the raw key byte length of X25519 (RFC 7748 §5); both
// private and public keys are 32 bytes.
const keySize = 32

// ErrInvalidKeyLength 表示传入的原始私钥 / 公钥字节数不是 X25519 规定的 32 字节。
//
// ErrInvalidKeyLength reports that a supplied raw key does not have the
// 32-byte length mandated by X25519.
var ErrInvalidKeyLength = fmt.Errorf("x25519: invalid key length, want %d bytes", keySize)

// PrivateKey 表示 X25519 私钥，底层持有 *core.PKey 句柄。
//
// PrivateKey is an X25519 private key backed by an internal *core.PKey.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 X25519 公钥，底层持有 *core.PKey 句柄。
//
// PublicKey is an X25519 public key backed by an internal *core.PKey.
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成新的 X25519 密钥对。
//
// 底层失败时返回包装 OpError 的错误。
//
// GenerateKey generates a fresh X25519 ECDH key pair.
//
// On failure it returns an error wrapping an OpError.
func GenerateKey() (*PrivateKey, error) {
	k, err := core.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// PrivateKeyFromBytes 从 32 字节原始私钥构造 *PrivateKey。
//
// raw 长度必须为 32 字节；其他长度返回 ErrInvalidKeyLength。
// 调用方在调用后须自行清零 raw。
//
// PrivateKeyFromBytes constructs an X25519 private key from 32 raw bytes.
//
// raw must be exactly 32 bytes; other lengths return ErrInvalidKeyLength.
// The caller is responsible for zeroising raw after the call.
func PrivateKeyFromBytes(raw []byte) (*PrivateKey, error) {
	if len(raw) != keySize {
		return nil, ErrInvalidKeyLength
	}
	k, err := core.NewRawPrivateKey(native.EvpPkeyX25519, raw)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// PublicKeyFromBytes 从 32 字节公钥字节构造 *PublicKey。
//
// raw 长度必须为 32 字节；其他长度返回 ErrInvalidKeyLength。
//
// PublicKeyFromBytes constructs an X25519 public key from 32 raw bytes.
//
// raw must be exactly 32 bytes; other lengths return ErrInvalidKeyLength.
func PublicKeyFromBytes(raw []byte) (*PublicKey, error) {
	if len(raw) != keySize {
		return nil, ErrInvalidKeyLength
	}
	k, err := core.NewRawPublicKey(native.EvpPkeyX25519, raw)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
//
// Key returns the underlying *core.PKey. It is intended for internal
// cross-package use and is not part of the stable public API.
func (k *PrivateKey) Key() *core.PKey { return k.key }

// Key 返回底层核心密钥对象（供内部跨包使用，如 x509）。
//
// Key returns the underlying *core.PKey. It is intended for internal
// cross-package use and is not part of the stable public API.
func (k *PublicKey) Key() *core.PKey { return k.key }

// Public 返回对应的公钥（引用同一底层密钥）；返回的 *PublicKey 包装同一个底层 *core.PKey，
// 对一侧执行的密码学操作在另一侧也可观察到。
//
// Public returns the public key associated with this private key; the
// returned *PublicKey wraps the same underlying *core.PKey and any
// cryptographic operation on one side is observable on the other.
func (k *PrivateKey) Public() (*PublicKey, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("x25519: nil private key")
	}
	return &PublicKey{key: k.key}, nil
}

// Bytes 导出 32 字节私钥字节。
//
// 失败时返回包装 OpError 的错误；调用方须自行清零返回的字节。
//
// Bytes exports the 32-byte raw private key.
//
// On failure it returns an error wrapping an OpError; the caller is
// responsible for zeroising the returned bytes.
func (k *PrivateKey) Bytes() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("x25519: nil private key")
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
		return nil, fmt.Errorf("x25519: nil public key")
	}
	return k.key.RawPublicKey()
}

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 X25519 私钥。
//
// 解析 PKCS#8（"-----BEGIN PRIVATE KEY-----"）PEM 块；底层走 EVP 通用路径。
// 失败时返回包装 OpError 的错误。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying a PKCS#8
// ("-----BEGIN PRIVATE KEY-----") X25519 private key. The Tongsuo EVP
// pipeline auto-detects the X25519 algorithm. On failure it returns an
// error wrapping an OpError.
func LoadPrivateKeyPEM(pemBytes []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 X25519 公钥。
//
// 解析 SPKI（"-----BEGIN PUBLIC KEY-----"）PEM 块；底层走 EVP 通用路径。
// 失败时返回包装 OpError 的错误。
//
// LoadPublicKeyPEM parses an unencrypted PEM block carrying a
// SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") X25519 public key.
// The Tongsuo EVP pipeline auto-detects the X25519 algorithm. On failure
// it returns an error wrapping an OpError.
func LoadPublicKeyPEM(pemBytes []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载 X25519 私钥。
//
// 解析加密 PEM 块（AES-256-CBC + PBKDF2 派生密钥，
// "-----BEGIN ENCRYPTED PRIVATE KEY-----"），使用给定口令；空口令或任意
// 解密错误返回错误。
//
// LoadEncryptedPEM parses an encrypted PEM block
// ("-----BEGIN ENCRYPTED PRIVATE KEY-----") using the given passphrase
// and returns the underlying X25519 private key. An empty passphrase or
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
		return nil, fmt.Errorf("x25519: nil private key")
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
		return nil, fmt.Errorf("x25519: nil private key")
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
		return nil, fmt.Errorf("x25519: nil public key")
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

// SharedSecret 计算本地私钥与对端公钥的 X25519 ECDH 共享密钥（32 字节）。
//
// priv 与 peer 算法须均为 X25519；算法不一致或底层 derive 失败时返回包装 OpError 的错误。
// 调用方应将返回的 shared 视为敏感数据并在使用后清零。
//
// SharedSecret computes the 32-byte X25519 ECDH shared secret between
// priv and peer.
//
// priv and peer must both be X25519 keys; algorithm mismatch or an
// underlying derive failure returns a wrapped OpError. Callers should
// treat the returned shared as sensitive and zeroise it after use.
func SharedSecret(priv *PrivateKey, peer *PublicKey) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("x25519: nil private key")
	}
	if peer == nil || peer.key == nil {
		return nil, fmt.Errorf("x25519: nil public key")
	}
	return priv.key.Derive(peer.key)
}

// Match 判断私钥与另一密钥（公钥/私钥/证书公钥）是否匹配；k 为 nil 或底层为 nil 时返回 false。
//
// 仅比较公钥分量（SPKI DER）；私钥与其内嵌的公钥天然匹配。供 x509 等跨包配对
// 使用，不属于稳定公共 API。
//
// Match reports whether the public component of this private key equals
// the public component of other (which may be a private key, public key,
// or certificate public key). Returns false when k or k.key is nil.
// It compares only the public SPKI DER. Intended for cross-package use
// and not part of the stable public API.
func (k *PrivateKey) Match(other *core.PKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(other)
}