// Package ecdsa 基于铜锁原生实现实现 ECDSA 非对称算法。
// 提供密钥生成、PEM 序列化、签名 / 验签（ECDSA-SHA256，ASN.1 DER）与参数提取。
// 摘要固定为 SHA-256（铜锁底层 EVP 管线决定）；需要其它摘要的调用方须自行
// 预哈希后再调用 Sign / Verify。
//
// Package ecdsa provides ECDSA (Elliptic Curve Digital Signature
// Algorithm) primitives backed by the Tongsuo native library. It exposes
// key generation, PEM (de)serialization for PKCS#8 private keys and
// SubjectPublicKeyInfo public keys, ECDSA-SHA256 sign / verify (ASN.1
// DER signatures) and EC parameter extraction. The digest is fixed to
// SHA-256 by the underlying EVP pipeline; callers who need a different
// digest must hash the data themselves before calling Sign / Verify.
package ecdsa

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PrivateKey 表示 ECDSA 私钥，底层持有 *core.PKey 句柄。
//
// PrivateKey is an ECDSA private key backed by an internal *core.PKey.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 ECDSA 公钥，底层持有 *core.PKey 句柄。
//
// PublicKey is an ECDSA public key backed by an internal *core.PKey.
type PublicKey struct {
	key *core.PKey
}

// GenerateKey 生成指定曲线的 EC 密钥对（curve 如 "prime256v1"、"secp384r1"、"sm2"）。
// curve 不能为空；底层失败返回错误。
//
// curve 必须非空并透传到铜锁 EVP 管线；常用值 "prime256v1"、"secp384r1"、
// "secp521r1" 与 "sm2"。失败时返回包装 OpError 的错误。
//
// GenerateKey generates an ECDSA key pair on the given curve.
//
// curve must be non-empty and is forwarded to the underlying Tongsuo EVP
// pipeline; common values include "prime256v1", "secp384r1", "secp521r1"
// and "sm2". On failure it returns an error wrapping an OpError.
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

// Public 返回对应的公钥（引用同一底层密钥）；返回的 *PublicKey 包装同一个底层 *core.PKey，对一侧执行的签名或密码学操作在另一侧也可观察到。
//
// Public returns the public key associated with this private key; the
// returned *PublicKey wraps the same underlying *core.PKey and any
// signature or cipher operation on one side is observable on the other.
func (k *PrivateKey) Public() *PublicKey { return &PublicKey{key: k.key} }

// LoadPrivateKeyPEM 从 PEM（PKCS#8）加载 ECDSA 私钥。
// 解析非加密 PEM 块，携带 PKCS#8（"-----BEGIN PRIVATE KEY-----"）ECDSA 私钥；
// 失败时返回包装 OpError 的错误。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying a PKCS#8
// ("-----BEGIN PRIVATE KEY-----") ECDSA private key and returns it.
// On failure it returns an error wrapping an OpError.
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 ECDSA 公钥。
// 解析非加密 PEM 块，携带 SubjectPublicKeyInfo（"-----BEGIN PUBLIC KEY-----"）
// ECDSA 公钥；失败时返回包装 OpError 的错误。
//
// LoadPublicKeyPEM parses an unencrypted PEM block carrying a
// SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") ECDSA public key
// and returns it. On failure it returns an error wrapping an OpError.
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载 ECDSA 私钥。
// 解析加密 PEM 块（AES-256-CBC + PBKDF2 派生密钥，
// "-----BEGIN ENCRYPTED PRIVATE KEY-----"），使用给定口令；空口令或任意
// 解密错误返回错误。
//
// LoadEncryptedPEM parses an encrypted PEM block (AES-256-CBC +
// PBKDF2-derived key, "-----BEGIN ENCRYPTED PRIVATE KEY-----") using the
// given passphrase and returns the underlying private key. An empty
// passphrase or any decryption error returns an error.
func LoadEncryptedPEM(pem []byte, pass string) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pem, pass)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
// 以 PKCS#8 PEM 块（"-----BEGIN PRIVATE KEY-----"）编码私钥；失败时返回
// wrapping OpError 的错误。
//
// MarshalPEM encodes the private key as a PKCS#8 PEM block
// ("-----BEGIN PRIVATE KEY-----"). On failure it returns an error
// wrapping an OpError.
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalEncryptedPEM 用口令加密导出私钥为 PEM（AES-256-CBC）。
// 以加密 PEM 块（"-----BEGIN ENCRYPTED PRIVATE KEY-----"）编码私钥，
// 口令作为 AES-256-CBC + PBKDF2 密钥派生基础；空口令或任意底层失败返回错误。
//
// MarshalEncryptedPEM encodes the private key as an encrypted PEM block
// ("-----BEGIN ENCRYPTED PRIVATE KEY-----") using the given passphrase
// as the basis for an AES-256-CBC + PBKDF2 key. An empty passphrase or
// any underlying failure returns an error.
func (k *PrivateKey) MarshalEncryptedPEM(pass string) ([]byte, error) {
	return k.key.MarshalEncryptedPEM(pass)
}

// MarshalPEM 导出公钥为 PEM（SubjectPublicKeyInfo）。
// 以 SubjectPublicKeyInfo PEM 块（"-----BEGIN PUBLIC KEY-----"）编码公钥；
// 失败时返回包装 OpError 的错误。
//
// MarshalPEM encodes the public key as a SubjectPublicKeyInfo PEM block
// ("-----BEGIN PUBLIC KEY-----"). On failure it returns an error
// wrapping an OpError.
func (k *PublicKey) MarshalPEM() ([]byte, error) {
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

// Params 返回 EC 参数（Curve / X / Y 公钥点，D 私钥标量）。
// 返回密钥的 EC 参数：Curve 标识符、(X, Y) 公钥仿射坐标；私钥侧还有 D 标量分量。
//
// Params returns the EC parameters of the key: the Curve identifier, the
// (X, Y) public affine coordinates, and for the private side the D
// (scalar) component.
func (k *PrivateKey) Params() *core.KeyParams { return k.key.Params() }

// Params 返回 EC 参数（Curve / X / Y 公钥点）。
// 返回公钥的 EC 参数：Curve 标识符与 (X, Y) 公钥仿射坐标。
//
// Params returns the EC parameters of the public key: the Curve
// identifier and the (X, Y) public affine coordinates.
func (k *PublicKey) Params() *core.KeyParams { return k.key.Params() }

// Sign 使用 ECDSA-SHA256 对 data 签名，返回 ASN.1 DER 签名。
// priv 为 nil 或底层为 nil 时返回错误。
//
// 摘要固定为 SHA-256；priv 或 priv.key 为 nil 时返回错误。调用方所需的非确定性
// （RFC 6979）行为由铜锁 EVP 层继承，本函数不直接暴露 k 参数。
//
// Sign produces an ECDSA-SHA256 signature over data and returns it in
// ASN.1 DER encoding.
//
// The digest is fixed to SHA-256 by the underlying pipeline. Returns an
// error when priv or priv.key is nil. Callers needing non-deterministic
// (RFC 6979) behaviour inherit it from Tongsuo's EVP layer; this function
// does not surface the k parameter directly.
func Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("ecdsa: nil private key")
	}
	return priv.key.SignDigest(data, core.SHA256())
}

// Verify 使用 ECDSA-SHA256 验签（签名须为 ASN.1 DER）。
// pub 为 nil、底层为 nil 或签名 DER 解析失败时返回错误。
//
// sig 必须为合法 ASN.1 DER 签名；摘要固定为 SHA-256 且须与 Sign 输出一致。pub 为
// nil、DER 无法解析或签名不通过时返回错误（绝不返回布尔值）；调用方应将任意
// 非 nil 错误视为认证失败，无需进一步区分原因。
//
// Verify checks an ECDSA-SHA256 signature sig against data using pub.
//
// sig must be a valid ASN.1 DER signature; the digest is fixed to SHA-256
// and must match what Sign produced. Returns an error (and never a
// boolean) when pub is nil, the DER cannot be parsed, or the signature
// does not verify — callers should treat any non-nil error as
// authentication failure without inspecting it.
func Verify(pub *PublicKey, data, sig []byte) error {
	if pub == nil || pub.key == nil {
		return fmt.Errorf("ecdsa: nil public key")
	}
	return pub.key.VerifyDigest(data, sig, core.SHA256())
}

// Match 判断私钥与另一密钥（公钥/私钥/证书公钥）是否匹配；k 为 nil 或底层为 nil 时返回 false。
// 判断本私钥的公钥分量是否与 other（可为私钥、公钥或证书公钥）的公钥分量相等。
// k 或 k.key 为 nil 时返回 false；仅用于跨包（如 x509 中证书与密钥配对），
// 不属于稳定公共 API。
//
// Match reports whether the public component of this private key equals
// the public component of other (which may be a private key, public key,
// or certificate public key). Returns false when k or k.key is nil.
// It is intended for cross-package use (e.g. certificate / key pairing
// in x509) and is not part of the stable public API.
func (k *PrivateKey) Match(other *core.PKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(other)
}
