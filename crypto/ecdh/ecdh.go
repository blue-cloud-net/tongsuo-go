// Package ecdh 基于铜锁原生实现 ECDH 密钥协商。
// 提供 NIST 曲线（P-256 / P-384 / P-521 / secp256k1，X9.63）与 OKP 曲线
// （X25519 / X448，RFC 7748）的密钥生成、PEM（PKCS#8 / SPKI）加载与序列化，
// 以及共享密钥计算。NIST 曲线的共享密钥为原始 X 坐标（定长），X25519 / X448
// 为标量乘输出（32 / 56 字节），均与 Go 标准库 crypto/ecdh、
// `openssl pkeyutl -derive` 一致。曲线抽象为 Curve，风格对齐 Go 标准库
// crypto/ecdh。调用方应把共享密钥视为敏感数据，使用完毕后自行清零。
//
// Package ecdh implements ECDH key agreement backed by the Tongsuo native
// library. It exposes key generation, PEM (PKCS#8 / SPKI) loading and
// serialization, and shared-secret derivation for the NIST curves
// (P-256 / P-384 / P-521 / secp256k1, X9.63) and the OKP curves
// (X25519 / X448, RFC 7748). The shared secret is the raw X coordinate at
// fixed field length for NIST curves and the raw scalar-multiplication
// output (32 / 56 bytes) for X25519 / X448, matching Go's crypto/ecdh and
// `openssl pkeyutl -derive`. Curves are abstracted behind Curve in the
// style of the Go standard crypto/ecdh package. Callers should treat the
// shared secret as sensitive data and zeroise it after use.
package ecdh

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// curveKind 区分曲线的实现族：NIST 曲线走 EC keygen 与通用 derive，
// X25519 / X448 走 OKP（EVP_PKEY_Q_keygen + 原始字节）路径。
//
// curveKind distinguishes the curve implementation families: NIST curves
// use the EC keygen / generic derive path, while X25519 and X448 use the
// OKP path (EVP_PKEY_Q_keygen plus raw key bytes).
type curveKind uint8

const (
	kindNIST   curveKind = iota // P-256 / P-384 / P-521 / secp256k1
	kindX25519                  // RFC 7748 X25519
	kindX448                    // RFC 7748 X448
)

// isOKP 报告该曲线是否属于 OKP（X25519 / X448）实现族。
//
// isOKP reports whether the curve belongs to the OKP family (X25519 / X448).
func (k curveKind) isOKP() bool { return k == kindX25519 || k == kindX448 }

// Curve 表示一条 ECDH 曲线（NIST prime256v1 / secp384r1 / secp521r1 /
// secp256k1，即 P-256 / P-384 / P-521 / secp256k1，以及 RFC 7748 的
// X25519 / X448）。
//
// Curve represents an ECDH curve. The current set covers the NIST curves
// prime256v1 / secp384r1 / secp521r1 / secp256k1 (P-256 / P-384 / P-521 /
// secp256k1) and the RFC 7748 curves X25519 / X448.
type Curve struct {
	kind curveKind // 实现族：NIST 或 OKP
	name string    // 展示名：P-256 / P-384 / P-521 / secp256k1 / X25519 / X448
	ossl string    // 铜锁曲线名（仅 NIST 使用）：prime256v1 / secp384r1 / ...
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

// Secp256k1 返回 secp256k1 曲线（非 NIST 标准曲线，比特币等生态常用）。
//
// 曲线可用性取决于运行时铜锁 provider；provider 不支持时 GenerateKey 会返回
// 包装 OpError 的错误。
//
// Secp256k1 returns the secp256k1 curve (not a NIST curve; widely used in
// the Bitcoin ecosystem).
//
// Availability depends on the runtime Tongsuo provider; when the curve is
// unsupported, GenerateKey returns an OpError-wrapped error.
func Secp256k1() *Curve { return &Curve{name: "secp256k1", ossl: "secp256k1"} }

// X25519 返回 X25519 曲线（RFC 7748，32 字节共享密钥，非 NIST 椭圆曲线）。
//
// 与 NIST 曲线不同，X25519 的密钥由 core.GenerateX25519Key 生成，加载后的
// 校验走 Algorithm() == "X25519"，共享密钥长度固定为 32 字节。
//
// X25519 returns the X25519 curve (RFC 7748, 32-byte shared secret, not a
// NIST elliptic curve).
//
// Unlike the NIST curves, X25519 keys are produced by
// core.GenerateX25519Key; loaded keys are validated through
// Algorithm() == "X25519" and the shared secret is always 32 bytes.
func X25519() *Curve { return &Curve{kind: kindX25519, name: "X25519"} }

// X448 返回 X448 曲线（RFC 7748，56 字节共享密钥，非 NIST 椭圆曲线）。
//
// 实现路径与 X25519 相同（OKP 族），差异仅在密钥 / 共享密钥长度（56 字节）
// 与 Algorithm() == "X448" 校验。
//
// X448 returns the X448 curve (RFC 7748, 56-byte shared secret, not a NIST
// elliptic curve).
//
// It follows the same OKP path as X25519; only the key / shared-secret
// length (56 bytes) and the Algorithm() == "X448" check differ.
func X448() *Curve { return &Curve{kind: kindX448, name: "X448"} }

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
	// OKP 曲线（X25519 / X448）在 OpenSSL 中经 EVP_PKEY_Q_keygen 单独生成，
	// 不走 EC keygen 路径。
	switch c.kind {
	case kindX25519:
		k, err := core.GenerateX25519Key()
		if err != nil {
			return nil, err
		}
		return &PrivateKey{key: k}, nil
	case kindX448:
		k, err := core.GenerateX448Key()
		if err != nil {
			return nil, err
		}
		return &PrivateKey{key: k}, nil
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
// EVP 读取路径自动识别。加载后校验密钥确为请求曲线上的密钥：NIST 曲线要求
// EC 类型且曲线名匹配，X25519 / X448 要求 Algorithm() 匹配（SM2/RSA 与不
// 匹配的曲线均报错）。失败时返回包装 OpError 的错误。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying an ECDH
// private key on the given curve. Both PKCS#8 ("-----BEGIN PRIVATE
// KEY-----") and traditional SEC1 ("-----BEGIN EC PRIVATE KEY-----")
// blocks are accepted via the OpenSSL EVP auto-detection path. After
// loading, the key is validated against the requested curve: NIST curves
// require an EC key with a matching curve name, while X25519 / X448
// require a matching Algorithm() (SM2/RSA keys and curve mismatches
// return an error). On failure it returns an error wrapping an OpError.
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
// 解析 SPKI（"-----BEGIN PUBLIC KEY-----"）PEM 块；加载后校验密钥属于请求
// 曲线（NIST 曲线要求 EC 类型且曲线名匹配，X25519 / X448 要求 Algorithm()
// 匹配；SM2/RSA 与不匹配的曲线均报错）。失败时返回包装 OpError 的错误。
//
// LoadPublicKeyPEM parses an unencrypted PEM block carrying a
// SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") ECDH public key on
// the given curve. After loading, the key is validated against the
// requested curve (NIST curves require an EC key with a matching curve
// name; X25519 / X448 require a matching Algorithm(); SM2/RSA keys and
// curve mismatches return an error). On failure it returns an error
// wrapping an OpError.
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

// ECDH 计算本地私钥与对端公钥之间的 ECDH 共享密钥。
//
// NIST 曲线返回原始 X 坐标（定长），X25519 / X448 返回 32 / 56 字节的标量乘
// 输出。本地私钥与对端公钥必须属于同一曲线；算法族或曲线不一致、底层 derive
// 失败（含 OKP 低阶点导致的全零结果）时返回错误。调用方应把返回的 shared
// 视为敏感数据并在使用后清零。
//
// ECDH computes the ECDH shared secret between k and peer.
//
// NIST curves return the raw X coordinate at fixed field length; X25519 and
// X448 return the 32 / 56-byte scalar-multiplication output. The local
// private key and the peer public key must be on the same curve; an
// algorithm-family or curve mismatch, or an underlying derive failure
// (including the all-zero result produced by OKP low-order points), returns
// an error. Callers should treat the returned shared secret as sensitive
// and zeroise it after use.
func (k *PrivateKey) ECDH(peer *PublicKey) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("ecdh: nil private key")
	}
	if peer == nil || peer.key == nil {
		return nil, fmt.Errorf("ecdh: nil public key")
	}
	algA, algB := k.key.Algorithm(), peer.key.Algorithm()
	// OKP 曲线（X25519 / X448）不是 EC：KeyParams 不带曲线名，改走 Algorithm 校验；
	// 同时显式拒绝 Ed25519 / Ed448 等其它非 EC 算法，不再依赖 Params 的偶然结果。
	if isOKPAlgorithm(algA) || isOKPAlgorithm(algB) {
		if algA != algB {
			return nil, fmt.Errorf("ecdh: curve mismatch: %q vs %q", algA, algB)
		}
		return k.key.Derive(peer.key)
	}
	a, b := k.key.Params(), peer.key.Params()
	if a == nil || b == nil || a.Type != "EC" || b.Type != "EC" ||
		a.Curve == "" || a.Curve != b.Curve {
		return nil, fmt.Errorf("ecdh: curve mismatch: %q vs %q", curveName(a, algA), curveName(b, algB))
	}
	return k.key.Derive(peer.key)
}

// match 校验加载的 *core.PKey 属于 c 曲线（EC 或 OKP，而非 SM2 / RSA / 其它）。
//
// OKP 曲线（X25519 / X448）走 Algorithm() 相等校验，不参与 EC 曲线名校验；
// 其余曲线要求 Type == "EC" 且曲线名与构造曲线一致。
//
// match validates that k belongs to curve c (EC or OKP, not SM2 / RSA / any
// other algorithm).
//
// OKP curves (X25519 / X448) are validated through Algorithm() equality and
// skip the EC curve-name check; all other curves require Type == "EC" and a
// curve name matching the constructed curve.
func (c *Curve) match(k *core.PKey) error {
	if c.kind.isOKP() {
		if k.Algorithm() != c.name {
			return fmt.Errorf("ecdh: key is not %s (got %s)", c.name, k.Algorithm())
		}
		return nil
	}
	p := k.Params()
	if p == nil || p.Type != "EC" {
		return fmt.Errorf("ecdh: key is not an EC key on %s", c.name)
	}
	if p.Curve != c.ossl {
		return fmt.Errorf("ecdh: key curve %q does not match %s", p.Curve, c.name)
	}
	return nil
}

// isOKPAlgorithm 报告算法名是否为 OKP 密钥交换算法（X25519 / X448）。
//
// isOKPAlgorithm reports whether alg denotes an OKP key-agreement algorithm
// (X25519 or X448).
func isOKPAlgorithm(alg string) bool {
	return alg == "X25519" || alg == "X448"
}

// curveName 取参数中的曲线名；OKP 曲线返回算法名，params 为 nil 时返回 "<unknown>"。
//
// curveName returns the curve name from params; OKP curves report their
// algorithm name and a nil params returns "<unknown>".
func curveName(p *core.KeyParams, alg string) string {
	if isOKPAlgorithm(alg) {
		return alg
	}
	if p == nil {
		return "<unknown>"
	}
	return p.Curve
}
