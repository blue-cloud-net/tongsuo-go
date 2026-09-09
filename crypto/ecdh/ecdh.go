// Package ecdh 基于铜锁原生实现 NIST 椭圆曲线 ECDH 密钥协商（X9.63）。
// 提供 P-256 / P-384 / P-521 三套曲线的密钥生成、PEM（PKCS#8 / SPKI）加载与
// 序列化，以及共享密钥计算。共享密钥为原始 X 坐标（定长，与 Go 标准库
// crypto/ecdh、`openssl pkeyutl -derive` 一致）。曲线抽象为 Curve，风格对齐
// Go 标准库 crypto/ecdh；后续可平滑扩展 X25519 等曲线而不破坏既有 API。
// 调用方应把共享密钥视为敏感数据，使用完毕后自行清零。
//
// Package ecdh implements NIST elliptic-curve ECDH key agreement
// (X9.63) backed by the Tongsuo native library. It exposes key
// generation, PEM (PKCS#8 / SPKI) loading and serialization, and
// shared-secret derivation for the P-256 / P-384 / P-521 curves. The
// shared secret is the raw X coordinate at fixed field length, matching
// Go's crypto/ecdh and `openssl pkeyutl -derive`. Curves are abstracted
// behind Curve in the style of the Go standard crypto/ecdh package, so
// additional curves such as X25519 can be added later without breaking
// the API. Callers should treat the shared secret as sensitive data and
// zeroise it after use.
package ecdh

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Curve 表示一条 ECDH 椭圆曲线（当前为 NIST prime256v1 / secp384r1 /
// secp521r1，即 P-256 / P-384 / P-521）。
//
// Curve represents an ECDH elliptic curve. The current set covers the
// NIST prime256v1 / secp384r1 / secp521r1 curves (P-256 / P-384 /
// P-521).
type Curve struct {
	name string // 展示名：P-256 / P-384 / P-521
	ossl string // 铜锁曲线名：prime256v1 / secp384r1 / secp521r1
}

// P256 返回 P-256（prime256v1）曲线。
//
// P256 returns the P-256 (prime256v1) curve.
func P256() *Curve { return &Curve{name: "P-256", ossl: "prime256v1"} }

// P384 返回 P-384（secp384r1）曲线。
//
// P384 returns the P-384 (secp384r1) curve.
func P384() *Curve { return &Curve{name: "P-384", ossl: "secp384r1"} }

// P521 返回 P-521（secp521r1）曲线。
//
// P521 returns the P-521 (secp521r1) curve.
func P521() *Curve { return &Curve{name: "P-521", ossl: "secp521r1"} }

// Name 返回曲线展示名（如 "P-256"）。nil 接收者返回空字符串。
//
// Name returns the display name of the curve (for example "P-256"). A
// nil receiver returns an empty string.
func (c *Curve) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}

// GenerateKey 在曲线上生成一对新的 ECDH 密钥。
//
// 底层失败时返回包装 OpError 的错误。
//
// GenerateKey generates a fresh ECDH key pair on the curve.
//
// On failure it returns an error wrapping an OpError.
func (c *Curve) GenerateKey() (*PrivateKey, error) {
	if c == nil {
		return nil, fmt.Errorf("ecdh: nil curve")
	}
	k, err := core.GenerateECKey(c.ossl)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// PrivateKey 表示某条曲线上的 ECDH 私钥，底层持有 *core.PKey 句柄。
//
// PrivateKey is an ECDH private key backed by an internal *core.PKey.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示某条曲线上的 ECDH 公钥，底层持有 *core.PKey 句柄。
//
// PublicKey is an ECDH public key backed by an internal *core.PKey.
type PublicKey struct {
	key *core.PKey
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

// Public 返回对应的公钥（引用同一底层密钥）；返回的 *PublicKey 包装同一个底层
// *core.PKey，对一侧执行的密码学操作在另一侧也可观察到。
//
// Public returns the public key associated with this private key; the
// returned *PublicKey wraps the same underlying *core.PKey and any
// cryptographic operation on one side is observable on the other.
func (k *PrivateKey) Public() *PublicKey {
	if k == nil || k.key == nil {
		return nil
	}
	return &PublicKey{key: k.key}
}

// LoadPrivateKeyPEM 从 PEM 加载指定曲线上的 ECDH 私钥。
//
// 接受 PKCS#8（"-----BEGIN PRIVATE KEY-----"）与传统 SEC1
// （"-----BEGIN EC PRIVATE KEY-----"）两种 PEM 块；底层走 OpenSSL 通用
// EVP 读取路径自动识别。加载后校验密钥确为请求曲线的 EC 私钥（非 SM2/RSA、
// 曲线不匹配均报错）。失败时返回包装 OpError 的错误。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying an ECDH
// private key on the given curve. Both PKCS#8 ("-----BEGIN PRIVATE
// KEY-----") and traditional SEC1 ("-----BEGIN EC PRIVATE KEY-----")
// blocks are accepted via the OpenSSL EVP auto-detection path. After
// loading, the key is validated to be an EC private key on the requested
// curve (SM2/RSA keys and curve mismatches return an error). On failure
// it returns an error wrapping an OpError.
func LoadPrivateKeyPEM(c *Curve, pemBytes []byte) (*PrivateKey, error) {
	if c == nil {
		return nil, fmt.Errorf("ecdh: nil curve")
	}
	k, err := core.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	if err := c.match(k); err != nil {
		k.Close()
		return nil, err
	}
	return &PrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载指定曲线上的 ECDH 公钥。
//
// 解析 SPKI（"-----BEGIN PUBLIC KEY-----"）PEM 块；加载后校验密钥确为请求
// 曲线的 EC 公钥（SM2/RSA 与曲线不匹配均报错）。失败时返回包装 OpError 的错误。
//
// LoadPublicKeyPEM parses an unencrypted PEM block carrying a
// SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") ECDH public key on
// the given curve. After loading, the key is validated to be an EC public
// key on the requested curve (SM2/RSA keys and curve mismatches return an
// error). On failure it returns an error wrapping an OpError.
func LoadPublicKeyPEM(c *Curve, pemBytes []byte) (*PublicKey, error) {
	if c == nil {
		return nil, fmt.Errorf("ecdh: nil curve")
	}
	k, err := core.LoadPublicKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	if err := c.match(k); err != nil {
		k.Close()
		return nil, err
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载指定曲线上的 ECDH 私钥。
//
// 解析加密 PEM 块（AES-256-CBC + PBKDF2 派生密钥，
// "-----BEGIN ENCRYPTED PRIVATE KEY-----"），使用给定口令；空口令或任意
// 解密错误返回错误；加载后同样校验曲线。
//
// LoadEncryptedPEM parses an encrypted PEM block
// ("-----BEGIN ENCRYPTED PRIVATE KEY-----") using the given passphrase
// and returns the underlying ECDH private key on the given curve. An
// empty passphrase or any decryption error returns an error; the loaded
// key is curve-validated as well.
func LoadEncryptedPEM(c *Curve, pemBytes []byte, pass string) (*PrivateKey, error) {
	if c == nil {
		return nil, fmt.Errorf("ecdh: nil curve")
	}
	k, err := core.LoadPrivateKeyPEMEncrypted(pemBytes, pass)
	if err != nil {
		return nil, err
	}
	if err := c.match(k); err != nil {
		k.Close()
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
		return nil, fmt.Errorf("ecdh: nil private key")
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
		return nil, fmt.Errorf("ecdh: nil private key")
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
		return nil, fmt.Errorf("ecdh: nil public key")
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

// ECDH 计算本地私钥与对端公钥之间的 ECDH 共享密钥（原始 X 坐标，定长）。
//
// 本地私钥与对端公钥必须在同一曲线上；算法族或曲线不一致、底层 derive 失败时
// 返回包装 OpError 的错误。调用方应把返回的 shared 视为敏感数据并在使用后清零。
//
// ECDH computes the ECDH shared secret between k and peer, returned as
// the raw X coordinate at fixed field length.
//
// The local private key and the peer public key must be on the same
// curve; algorithm-family or curve mismatch, or an underlying derive
// failure, returns a wrapped OpError. Callers should treat the returned
// shared secret as sensitive and zeroise it after use.
func (k *PrivateKey) ECDH(peer *PublicKey) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ecdh: nil private key")
	}
	if peer == nil || peer.key == nil {
		return nil, fmt.Errorf("ecdh: nil public key")
	}
	a, b := k.key.Params(), peer.key.Params()
	if a == nil || b == nil || a.Curve == "" || a.Curve != b.Curve {
		return nil, fmt.Errorf("ecdh: curve mismatch: %q vs %q", curveName(a), curveName(b))
	}
	return k.key.Derive(peer.key)
}

// match 校验加载的 *core.PKey 是 c 曲线上的普通 EC 密钥（非 SM2/RSA）。
//
// match validates that k is a plain EC key on curve c (not SM2/RSA).
func (c *Curve) match(k *core.PKey) error {
	p := k.Params()
	if p == nil || p.Type != "EC" {
		return fmt.Errorf("ecdh: key is not an EC key on %s", c.name)
	}
	if p.Curve != c.ossl {
		return fmt.Errorf("ecdh: key curve %q does not match %s", p.Curve, c.name)
	}
	return nil
}

// curveName 取参数中的曲线名，nil 时返回 "<unknown>"。
//
// curveName returns the curve name from params, or "<unknown>" when
// params is nil.
func curveName(p *core.KeyParams) string {
	if p == nil {
		return "<unknown>"
	}
	return p.Curve
}
