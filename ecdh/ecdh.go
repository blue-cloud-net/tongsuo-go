// Package ecdh 基于铜锁原生实现 ECDH 密钥协商。
//
// 本包**只做密钥协商**：曲线标识（Curve）与共享密钥派生（SharedSecret /
// ECDH）。密钥生成、PEM 导入导出、签名验签统一由 asym 包提供；把 asym 的
// 密钥对象转成 ecdh 对象的入口是 LoadPrivateKey / LoadPublicKey，其内部经
// internal/keyaccess 结构化断言取到底层句柄并 EVP_PKEY_dup 复制，两侧生命
// 周期完全独立。
//
// 支持 NIST 曲线（P-256 / P-384 / P-521 / secp256k1，X9.63）与 OKP 曲线
// （X25519 / X448，RFC 7748）。NIST 曲线的共享密钥为原始 X 坐标（定长），
// X25519 / X448 为标量乘输出（32 / 56 字节），均与 Go 标准库 crypto/ecdh、
// `openssl pkeyutl -derive` 一致。调用方应把共享密钥视为敏感数据，使用完毕
// 后自行清零。
//
// Package ecdh implements ECDH key agreement backed by the Tongsuo native
// library.
//
// The package performs **key agreement only**: curve identification (Curve)
// and shared-secret derivation (SharedSecret / ECDH). Key generation, PEM
// import/export and signing all live in the asym package; LoadPrivateKey /
// LoadPublicKey convert an asym key object into an ecdh one, extracting the
// underlying handle through the internal/keyaccess structural assertion and
// copying it with EVP_PKEY_dup so the two sides have fully independent
// lifetimes.
//
// Supported curves are the NIST set (P-256 / P-384 / P-521 / secp256k1,
// X9.63) and the OKP set (X25519 / X448, RFC 7748). The shared secret is the
// raw X coordinate at fixed field length for NIST curves and the raw
// scalar-multiplication output (32 / 56 bytes) for X25519 / X448, matching
// Go's crypto/ecdh and `openssl pkeyutl -derive`. Callers should treat the
// shared secret as sensitive data and zeroise it after use.
package ecdh

import (
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/keyaccess"
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

// Curves 返回本版支持的曲线展示名（顺序稳定）。
//
// 对应铜锁 `openssl ecparam -list_curves` 中本包已封装的子集。
//
// Curves returns the display names of the curves supported by this
// version, in a stable order.
//
// It corresponds to the subset of `openssl ecparam -list_curves` that
// this package wraps.
func Curves() []string {
	all := allCurves()
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = c.name
	}
	return out
}

// CurveByName 按展示名构造曲线；未知名返回 ErrUnknownCurve。
//
// 名称大小写不敏感，并接受常见别名（"P-256" / "prime256v1" / "secp256r1"）。
//
// CurveByName constructs a curve by its display name; an unknown name
// returns ErrUnknownCurve.
//
// Matching is case-insensitive and accepts common aliases such as
// "P-256" / "prime256v1" / "secp256r1".
func CurveByName(name string) (*Curve, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	if key == "" {
		return nil, fmt.Errorf("%w: %q", ErrUnknownCurve, name)
	}
	for _, c := range allCurves() {
		if strings.ToUpper(c.name) == key {
			return c, nil
		}
		// OKP 曲线没有 openssl 曲线名，不可参与别名匹配（否则空串会命中）
		if c.ossl != "" && strings.ToUpper(c.ossl) == key {
			return c, nil
		}
	}
	switch key {
	case "P-256", "PRIME256V1", "SECP256R1":
		return P256(), nil
	case "P-384", "SECP384R1":
		return P384(), nil
	case "P-521", "SECP521R1":
		return P521(), nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownCurve, name)
}

// allCurves 返回全部内置曲线的实例（每次新构造，避免共享可变状态）。
//
// allCurves returns freshly constructed instances of every built-in
// curve, avoiding shared mutable state.
func allCurves() []*Curve {
	return []*Curve{P256(), P384(), P521(), Secp256k1(), X25519(), X448()}
}

// curveOf 由底层密钥反查曲线；无法识别时返回 nil。
//
// curveOf looks up the curve of an underlying key, returning nil when it
// cannot be identified.
func curveOf(k *core.PKey) *Curve {
	if k == nil {
		return nil
	}
	alg := k.Algorithm()
	if isOKPAlgorithm(alg) {
		c, err := CurveByName(alg)
		if err != nil {
			return nil
		}
		return c
	}
	p := k.Params()
	if p == nil || p.Type != "EC" {
		return nil
	}
	c, err := CurveByName(p.Curve)
	if err != nil {
		return nil
	}
	return c
}

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

// GenerateKey 已移除：曲线密钥生成统一走 asym。
//
// 迁移写法：
//
//	ecdh.P256().GenerateKey()            → asym.GenerateEC(asym.CurveP256) 后 ecdh.LoadPrivateKey
//
//	ecdh.X25519().GenerateKey()          → asym.GenerateX25519() 后 ecdh.LoadPrivateKey
//
// GenerateKey has been removed: curve key generation lives in asym now.
//
// Migration:
//
//	ecdh.P256().GenerateKey()            → asym.GenerateEC(asym.CurveP256) then ecdh.LoadPrivateKey
//
//	ecdh.X25519().GenerateKey()          → asym.GenerateX25519() then ecdh.LoadPrivateKey

// PrivateKey 表示某条曲线上的 ECDH 私钥，底层持有原生 EVP_PKEY 句柄
// （不对外暴露，公开签名中不出现任何 internal 类型）。
//
// 经 LoadPrivateKey / LoadPrivateKeyPEM 构造；本包不提供生成入口。
//
// PrivateKey is an ECDH private key backed by a native EVP_PKEY handle
// (never exposed; no internal type appears in the public signatures).
//
// It is constructed through LoadPrivateKey / LoadPrivateKeyPEM; this
// package offers no generation entry point.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示某条曲线上的 ECDH 公钥，底层持有原生 EVP_PKEY 句柄
// （不对外暴露）。
//
// PublicKey is an ECDH public key backed by a native EVP_PKEY handle
// (never exposed).
type PublicKey struct {
	key *core.PKey
}

// Public 返回对应的公钥（共享同一底层句柄）；因此对一侧执行的密码学操作
// 在另一侧也可观察到。
//
// Public returns the public key associated with this private key, sharing
// the same underlying handle; any cryptographic operation on one side is
// therefore observable on the other.
func (k *PrivateKey) Public() *PublicKey {
	if k == nil || k.key == nil {
		return nil
	}
	return &PublicKey{key: k.key}
}

// Curve 返回该私钥所在的曲线；无法识别时返回 nil。
//
// Curve returns the curve this private key belongs to, or nil when it
// cannot be identified.
func (k *PrivateKey) Curve() *Curve {
	if k == nil || k.key == nil {
		return nil
	}
	return curveOf(k.key)
}

// Curve 返回该公钥所在的曲线；无法识别时返回 nil。
//
// Curve returns the curve this public key belongs to, or nil when it
// cannot be identified.
func (k *PublicKey) Curve() *Curve {
	if k == nil || k.key == nil {
		return nil
	}
	return curveOf(k.key)
}

// LoadPrivateKey 由 asym 私钥对象构造 ECDH 私钥。
//
// 取值路径：asym 的密钥具体类型非导出且实现了导出方法 `CorePKey()`，
// internal/keyaccess 以结构化接口断言识别；取到句柄后立即复制一份，因此本
// 对象与原 asym 密钥生命周期完全独立。公开签名中不出现任何 internal 类型。
//
// 仅接受 NIST 曲线（P-256 / P-384 / P-521 / secp256k1）与 OKP 曲线
// （X25519 / X448）的密钥；RSA / Ed25519 / Ed448 / SM2 与任何非 EC / OKP
// 密钥返回 ErrUnsupportedKey。
//
// LoadPrivateKey constructs an ECDH private key from an asym private key
// object.
//
// The handle is obtained through the internal/keyaccess structural
// assertion against the exported `CorePKey()` method that asym's
// unexported concrete types implement, and is then copied, so this
// object's lifetime is fully independent of the source asym key. No
// internal type appears in the public signature.
//
// Only NIST curves (P-256 / P-384 / P-521 / secp256k1) and OKP curves
// (X25519 / X448) are accepted; RSA / Ed25519 / Ed448 / SM2 and any other
// non-EC / non-OKP key returns ErrUnsupportedKey.
func LoadPrivateKey(k asym.PrivateKey) (*PrivateKey, error) {
	if k == nil {
		return nil, fmt.Errorf("ecdh: nil private key")
	}
	src, ok := keyaccess.PKey(k)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, k.Algorithm())
	}
	// keyaccess 的契约：取到的句柄由源对象持有，必须立即 Dup。
	dup, err := src.Dup()
	if err != nil {
		return nil, err
	}
	if c := curveOf(dup); c == nil {
		_ = dup.Close()
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, dup.Algorithm())
	}
	return &PrivateKey{key: dup}, nil
}

// LoadPublicKey 由 asym 公钥对象构造 ECDH 公钥。
//
// 机制与限制同 LoadPrivateKey（同样经 internal/keyaccess + EVP_PKEY_dup）。
//
// LoadPublicKey constructs an ECDH public key from an asym public key
// object.
//
// The mechanism and restrictions match LoadPrivateKey (also going through
// internal/keyaccess plus EVP_PKEY_dup).
func LoadPublicKey(k asym.PublicKey) (*PublicKey, error) {
	if k == nil {
		return nil, fmt.Errorf("ecdh: nil public key")
	}
	src, ok := keyaccess.PKey(k)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, k.Algorithm())
	}
	dup, err := src.Dup()
	if err != nil {
		return nil, err
	}
	if c := curveOf(dup); c == nil {
		_ = dup.Close()
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, dup.Algorithm())
	}
	return &PublicKey{key: dup}, nil
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
	return SharedSecret(k, peer)
}

// SharedSecret 派生共享密钥的包级形式（原 crypto/x25519.SharedSecret /
// crypto/x448.SharedSecret）。
//
// 与本包的 ECDH 方法等价，便于按函数式风格调用及从 x25519 / x448 包迁移。
// 返回值应视为敏感数据，使用完毕后自行清零。
//
// SharedSecret is the package-level form of the shared-secret derivation
// (originally crypto/x25519.SharedSecret and crypto/x448.SharedSecret).
//
// It is equivalent to the ECDH method and eases functional-style calls and
// migration from the x25519 / x448 packages. The returned value should be
// treated as sensitive and zeroised after use.
func SharedSecret(priv *PrivateKey, peer *PublicKey) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("ecdh: nil private key")
	}
	if peer == nil || peer.key == nil {
		return nil, fmt.Errorf("ecdh: nil public key")
	}
	algA, algB := priv.key.Algorithm(), peer.key.Algorithm()
	// OKP 曲线（X25519 / X448）不是 EC：KeyParams 不带曲线名，改走 Algorithm 校验；
	// 同时显式拒绝 Ed25519 / Ed448 等其它非 EC 算法，不再依赖 Params 的偶然结果。
	if isOKPAlgorithm(algA) || isOKPAlgorithm(algB) {
		if algA != algB {
			return nil, fmt.Errorf("ecdh: curve mismatch: %q vs %q", algA, algB)
		}
		return priv.key.Derive(peer.key)
	}
	a, b := priv.key.Params(), peer.key.Params()
	if a == nil || b == nil || a.Type != "EC" || b.Type != "EC" ||
		a.Curve == "" || a.Curve != b.Curve {
		return nil, fmt.Errorf("ecdh: curve mismatch: %q vs %q", curveName(a, algA), curveName(b, algB))
	}
	return priv.key.Derive(peer.key)
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
