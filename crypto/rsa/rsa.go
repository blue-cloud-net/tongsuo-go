// Package rsa 基于铜锁原生实现实现 RSA 非对称算法。
// 提供密钥生成、PEM 序列化（PKCS#8 / PKCS#1 / 加密）、签名（PKCS#1 v1.5 / PSS）、
// 加解密（PKCS#1 v1.5 / OAEP）与参数提取。签名默认使用 SHA-256 摘要。
// 密钥长度可控，最小 1024 位。所有 Sign / Verify 默认使用 SHA-256（RFC 8017）。
// PSS 调用方须自行提供 salt 长度（负值遵循 OpenSSL 约定：-1=摘要长度、-2=auto、-3=最大）。
//
// Package rsa provides RSA primitives backed by the Tongsuo native
// library. It exposes key generation (key size controllable, with a
// 1024-bit minimum), PEM (de)serialization for PKCS#8, PKCS#1 ("BEGIN
// RSA PRIVATE KEY") and encrypted private keys plus SubjectPublicKeyInfo
// public keys, PKCS#1 v1.5 signatures, PSS signatures, PKCS#1 v1.5 public
// encryption and OAEP public encryption, and RSA parameter extraction.
// All Sign / Verify helpers below default to SHA-256 (RFC 8017); PSS
// callers supply their own salt length (negative values follow the
// OpenSSL conventions -1=digest length, -2=auto, -3=maximum).
package rsa

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PrivateKey 表示 RSA 私钥，底层持有 *core.PKey 句柄。
//
// PrivateKey is an RSA private key backed by an internal *core.PKey.
type PrivateKey struct {
	key *core.PKey
}

// PublicKey 表示 RSA 公钥，底层持有 *core.PKey 句柄。
//
// PublicKey is an RSA public key backed by an internal *core.PKey.
type PublicKey struct {
	key *core.PKey
}

// PSS 盐长哨兵常量，供 SignPSS / VerifyPSS 的 saltLen 参数使用。
//
// 负值遵循 OpenSSL EVP_PKEY_CTX_set_rsa_pss_saltlen 约定：
//
//	PSSSaltLenDigest 盐长 = 摘要长度（本库默认摘要为 SHA-256，故为 32）
//	PSSSaltLenAuto   由底层自动选择（provider 决定）
//	PSSSaltLenMax    取模数允许的最大盐长
//
// 也可直接传正整数指定盐长字节数；SignPSS 与 VerifyPSS 必须使用相同取值。
//
// PSS salt-length sentinel constants for the saltLen argument of
// SignPSS / VerifyPSS. Negative values follow the OpenSSL
// EVP_PKEY_CTX_set_rsa_pss_saltlen convention: PSSSaltLenDigest means
// the salt equals the digest length (32 for the default SHA-256),
// PSSSaltLenAuto leaves the choice to the underlying provider, and
// PSSSaltLenMax selects the largest salt the modulus allows. Positive
// integers are also accepted as an explicit salt length in bytes;
// SignPSS and VerifyPSS must use the same value.
const (
	PSSSaltLenDigest = -1
	PSSSaltLenAuto   = -2
	PSSSaltLenMax    = -3
)

// GenerateKey 生成 bits 位 RSA 密钥对（如 2048）。
// bits 须 >= 1024，否则返回错误。
//
// bits 必须至少 1024（与 SP 800-131A 及 FIPS 186-4 最小模数对齐，更小将被拒绝）；
// 铜锁侧失败时返回包装 OpError 的错误。
//
// GenerateKey generates an RSA key pair of the given bit size.
//
// bits must be at least 1024; values below that are rejected to match
// SP 800-131A and FIPS 186-4 minimum moduli. On Tongsuo-side failure it
// returns an error wrapping an OpError.
func GenerateKey(bits int) (*PrivateKey, error) {
	if bits < 1024 {
		return nil, fmt.Errorf("rsa: key size too small: %d", bits)
	}
	k, err := core.GenerateRSAKey(bits)
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

// Public 返回对应的公钥（引用同一底层密钥）；返回的 *PublicKey 包装同一个底层 *core.PKey。
//
// Public returns the public key paired with this private key; the
// returned *PublicKey wraps the same underlying *core.PKey.
func (k *PrivateKey) Public() *PublicKey { return &PublicKey{key: k.key} }

// LoadPrivateKeyPEM 从 PEM 加载 RSA 私钥（PKCS#8 或 PKCS#1）。
// 解析非加密 PEM 块，可携带 PKCS#8（"-----BEGIN PRIVATE KEY-----"）或
// 传统 PKCS#1（"-----BEGIN RSA PRIVATE KEY-----"）RSA 私钥。优先尝试 PKCS#8，
// 失败后再尝试 PKCS#1；均失败时返回错误。
//
// 无论从哪条路径加载成功，都会校验底层密钥算法确为 RSA——若 PKCS#8 实际携带
// EC / SM2 密钥，返回错误而不是静默包装成 RSA（避免把类型混淆延迟到使用期）。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying either a
// PKCS#8 ("-----BEGIN PRIVATE KEY-----") or a legacy PKCS#1
// ("-----BEGIN RSA PRIVATE KEY-----") RSA private key. PKCS#8 is tried
// first; on PKCS#8 failure PKCS#1 is attempted. On total failure it
// returns an error.
//
// Whichever path succeeds, the underlying key algorithm is verified to be
// RSA: a PKCS#8 block that actually carries an EC / SM2 key returns an
// error instead of silently being wrapped as RSA (avoiding a type-confusion
// that would otherwise surface only at use time).
func LoadPrivateKeyPEM(pem []byte) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err == nil {
		if !isRSA(k) {
			alg := k.Algorithm() // 先读算法名再释放句柄
			k.Close()
			return nil, fmt.Errorf("rsa: PEM private key is not RSA (got %s)", alg)
		}
		return &PrivateKey{key: k}, nil
	}
	k2, err2 := core.LoadPrivateKeyPKCS1PEM(pem)
	if err2 != nil {
		// 两条路径均失败：返回同时说明 PKCS#8 与 PKCS#1 原因的合并错误，
		// 避免只暴露首个（对 PKCS#1 形状的输入，PKCS#8 失败属预期，PKCS#1
		// 失败才是真实原因）。
		return nil, fmt.Errorf("rsa: LoadPrivateKeyPEM: pkcs8: %v; pkcs1: %v", err, err2)
	}
	if !isRSA(k2) {
		alg := k2.Algorithm()
		k2.Close()
		return nil, fmt.Errorf("rsa: PEM private key is not RSA (got %s)", alg)
	}
	return &PrivateKey{key: k2}, nil
}

// isRSA 报告 *core.PKey 的底层算法是否为 RSA。
//
// isRSA reports whether the underlying key algorithm is RSA, by
// comparing core.PKey.Algorithm with the "RSA" algorithm name.
func isRSA(k *core.PKey) bool {
	return k != nil && k.Algorithm() == "RSA"
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 RSA 公钥。
// 解析非加密 PEM 块，携带 SubjectPublicKeyInfo（"-----BEGIN PUBLIC KEY-----"）
// RSA 公钥；失败时返回包装 OpError 的错误。
//
// 与 LoadPrivateKeyPEM 相同，会校验算法确为 RSA 再包装。
//
// LoadPublicKeyPEM parses an unencrypted PEM block carrying a
// SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") RSA public key.
// On failure it returns an error wrapping an OpError. As with
// LoadPrivateKeyPEM, the algorithm is verified to be RSA before
// wrapping.
func LoadPublicKeyPEM(pem []byte) (*PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	if !isRSA(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("rsa: PEM public key is not RSA (got %s)", alg)
	}
	return &PublicKey{key: k}, nil
}

// LoadEncryptedPEM 从加密 PEM 加载 RSA 私钥。
// 解析加密 PEM 块（AES-256-CBC + PBKDF2 派生密钥，
// "-----BEGIN ENCRYPTED PRIVATE KEY-----"），使用给定口令；口令错误或任意
// 解密错误返回错误。与 LoadPrivateKeyPEM 相同，加载后校验算法确为 RSA。
//
// LoadEncryptedPEM parses an encrypted PEM block (AES-256-CBC +
// PBKDF2-derived key, "-----BEGIN ENCRYPTED PRIVATE KEY-----") using the
// given passphrase and returns the underlying RSA private key. An
// incorrect passphrase or any decryption error returns an error. As
// with LoadPrivateKeyPEM, the algorithm is verified to be RSA.
func LoadEncryptedPEM(pem []byte, pass string) (*PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pem, pass)
	if err != nil {
		return nil, err
	}
	if !isRSA(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("rsa: encrypted PEM private key is not RSA (got %s)", alg)
	}
	return &PrivateKey{key: k}, nil
}

// MarshalPEM 导出私钥为 PEM（PKCS#8）。
// 以 PKCS#8 PEM 块（"-----BEGIN PRIVATE KEY-----"）编码 RSA 私钥；失败时返回
// 包装 OpError 的错误。
//
// MarshalPEM encodes the RSA private key as a PKCS#8 PEM block
// ("-----BEGIN PRIVATE KEY-----"). On failure it returns an error
// wrapping an OpError.
func (k *PrivateKey) MarshalPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalPKCS1PEM 导出私钥为 PKCS#1 PEM（"BEGIN RSA PRIVATE KEY"）。
// 以传统 PKCS#1 PEM 格式（"-----BEGIN RSA PRIVATE KEY-----"）编码 RSA 私钥。
// 新协议应优先使用 MarshalPEM（PKCS#8）；本函数仅用于兼容只接受传统格式的工具。
//
// MarshalPKCS1PEM encodes the RSA private key using the legacy PKCS#1
// PEM format ("-----BEGIN RSA PRIVATE KEY-----"). New protocols should
// prefer MarshalPEM (PKCS#8); this helper exists for compatibility with
// tools that only accept the traditional format.
func (k *PrivateKey) MarshalPKCS1PEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPKCS1PEM()
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

// Params 返回 RSA 参数（N/E 公钥，D/P/Q 私钥）；返回密钥的 RSA 参数：模数 N、公钥指数 E；私钥侧还有私钥指数 D 与 CRT 因子 P/Q。
//
// Params returns the RSA parameters of the key: the modulus N, the
// public exponent E, and for the private side the private exponent D and
// the CRT factors P and Q.
func (k *PrivateKey) Params() *core.KeyParams { return k.key.Params() }

// Params 返回 RSA 参数（N/E 公钥）；返回公钥的 RSA 参数：模数 N 与公钥指数 E。
//
// Params returns the RSA parameters of the public key: the modulus N and
// the public exponent E.
func (k *PublicKey) Params() *core.KeyParams { return k.key.Params() }

// SignPKCS1v15 使用 RSA-PKCS#1 v1.5 对 data 签名（SHA-256 摘要）。
// 以 RSA-PKCS#1 v1.5（RFC 8017）签名 data，底层摘要使用 SHA-256。
// PKCS#1 v1.5 兼容性最广；新协议推荐使用 SignPSS。
//
// SignPKCS1v15 signs data with RSA-PKCS#1 v1.5 (RFC 8017) using SHA-256
// as the underlying digest. PKCS#1 v1.5 has the broadest compatibility;
// new protocols should prefer SignPSS.
func (k *PrivateKey) SignPKCS1v15(data []byte) ([]byte, error) {
	return k.key.SignDigest(data, core.SHA256())
}

// VerifyPKCS1v15 使用 RSA-PKCS#1 v1.5 验签（SHA-256 摘要）。
// 以 RSA-PKCS#1 v1.5（RFC 8017）验签，摘要使用 SHA-256。sig 必须为 SignPKCS1v15
// 的输出；验签失败时返回错误（不返回布尔值），调用方须将任意非 nil 错误视为
// 认证失败。
//
// VerifyPKCS1v15 checks an RSA-PKCS#1 v1.5 (RFC 8017) signature over
// data using SHA-256 as the digest. sig must be exactly the output of
// SignPKCS1v15. Returns an error (no boolean) on verification failure.
// Callers must treat any non-nil error as authentication failure.
func (k *PublicKey) VerifyPKCS1v15(data, sig []byte) error {
	return k.key.VerifyDigest(data, sig, core.SHA256())
}

// SignPSS 使用 RSA-PSS 对 data 签名（SHA-256 摘要）。
// saltLen 为盐长：正整数 = 盐长字节数，或使用本包 PSS 哨兵常量
// （PSSSaltLenDigest / PSSSaltLenAuto / PSSSaltLenMax）。
//
// 以 RSA-PSS（RFC 8017）签名 data，摘要使用 SHA-256。VerifyPSS 须使用相同值。
//
// SignPSS signs data with RSA-PSS (RFC 8017) using SHA-256 as the digest.
//
// saltLen is the salt length: a positive integer in bytes, or one of the
// package's PSS sentinel constants (PSSSaltLenDigest / PSSSaltLenAuto /
// PSSSaltLenMax). VerifyPSS must use the same value.
func (k *PrivateKey) SignPSS(data []byte, saltLen int) ([]byte, error) {
	return k.key.SignDigestPSS(data, core.SHA256(), saltLen)
}

// VerifyPSS 使用 RSA-PSS 验签（SHA-256 摘要）。
// saltLen 必须与签名时一致（正整数或本包 PSS 哨兵常量）。
// 验签失败返回错误（不返回布尔值）；调用方须将任意非 nil
// 错误视为认证失败。
//
// VerifyPSS checks an RSA-PSS signature over data using SHA-256 as the
// digest; saltLen must equal the value used at sign time (a positive
// integer or one of the package's PSS sentinel constants). Returns an
// error (no boolean) on verification failure; callers must treat any
// non-nil error as authentication failure.
func (k *PublicKey) VerifyPSS(data, sig []byte, saltLen int) error {
	return k.key.VerifyDigestPSS(data, sig, core.SHA256(), saltLen)
}

// EncryptPKCS1v15 使用 RSA-PKCS#1 v1.5 填充加密（明文须短于模数）。
// pub 为 nil 时返回错误；不适合长消息或对抗主动攻击者，新协议推荐 OAEP。
//
// 以 RSA-PKCS#1 v1.5（RFC 8017）填充加密 data。密文长度等于公钥模数；data 必须
// 严格短于模数（RSAES-PKCS1-v1_5 上限）。EncryptPKCS1v15 存在已知 padding oracle
// 漏洞（Bleichenbacher），不适用于对抗场景——新协议必须使用 EncryptOAEP。pub 为 nil
// 或底层调用失败时返回错误。
//
// EncryptPKCS1v15 encrypts data with RSA-PKCS#1 v1.5 (RFC 8017) padding.
//
// The ciphertext length is the public modulus size. data must be strictly
// shorter than the modulus (RSAES-PKCS1-v1_5 maximum); EncryptPKCS1v15
// has known padding-oracle vulnerabilities (Bleichenbacher) and is not
// suitable for adversarial settings — new protocols must use
// EncryptOAEP. Returns an error when pub is nil or the underlying call
// fails.
func EncryptPKCS1v15(pub *PublicKey, data []byte) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("rsa: nil public key")
	}
	return pub.key.EncryptPKCS1v15(data)
}

// DecryptPKCS1v15 使用 RSA-PKCS#1 v1.5 填充解密。
// 与 EncryptPKCS1v15 互逆，并继承 Bleichenbacher padding oracle 同等限制：
// 任何解密失败须作为错误上报给调用方，且上层需做等时常时间处理（不可区分返回
// "invalid padding" 与 "invalid ciphertext"）。priv 为 nil 或填充校验失败时返回错误。
//
// DecryptPKCS1v15 inverts EncryptPKCS1v15 and inherits the same
// Bleichenbacher padding-oracle caveat: any decryption failure must be
// surfaced to callers as an error and the same constant-time treatment
// applies at the upper layer (don't return "invalid padding" vs
// "invalid ciphertext" distinctly). Returns an error when priv is nil
// or padding verification fails.
func DecryptPKCS1v15(priv *PrivateKey, data []byte) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("rsa: nil private key")
	}
	return priv.key.DecryptPKCS1v15(data)
}

// EncryptOAEP 使用 RSA-OAEP 填充加密。md 为 OAEP/MGF1 摘要（nil 时用 SHA-256）。
// pub 为 nil 时返回错误；md 须与解密时一致（nil 在两侧均默认 SHA-256）。
//
// 以 RSA-OAEP（RFC 8017）填充加密 data。md 同时选择 OAEP 编码哈希与 MGF1 哈希，
// 传 nil 则使用 SHA-256（MGF1 也使用 SHA-256）。密文长度等于模数长度；data 必须
// 短于模数减去 2*hashSize + 2 字节。pub 为 nil 或底层调用失败时返回错误。
// DecryptOAEP 必须使用相同的 md。
//
// EncryptOAEP encrypts data with RSA-OAEP (RFC 8017) padding.
//
// md selects both the OAEP encoding hash and the MGF1 hash; pass nil to
// use SHA-256 (MGF1 with SHA-256). The ciphertext length is the modulus
// size; data must be shorter than the modulus minus 2*hashSize - 2
// bytes. Returns an error when pub is nil or the underlying call fails.
// DecryptOAEP must use the same md.
func EncryptOAEP(pub *PublicKey, data []byte, md *core.Digest) ([]byte, error) {
	if pub == nil || pub.key == nil {
		return nil, fmt.Errorf("rsa: nil public key")
	}
	if md == nil {
		md = core.SHA256()
	}
	return pub.key.EncryptOAEP(data, md)
}

// DecryptOAEP 使用 RSA-OAEP 填充解密。md 须与加密时一致。
// priv 为 nil 时返回错误；md 与加密时的值必须一致（nil 同样默认 SHA-256）。
//
// 与 EncryptOAEP 互逆。md 必须与加密时一致（两侧传 nil 均默认 SHA-256）。priv 为 nil、
// 密文长度与模数不匹配、或 OAEP 标签 / 填充校验失败时返回错误。
//
// DecryptOAEP inverts EncryptOAEP.
//
// md must equal the value used at encryption time (pass nil to default to
// SHA-256 on both sides). Returns an error when priv is nil, when the
// ciphertext length mismatches the modulus, or when OAEP label / padding
// verification fails.
func DecryptOAEP(priv *PrivateKey, data []byte, md *core.Digest) ([]byte, error) {
	if priv == nil || priv.key == nil {
		return nil, fmt.Errorf("rsa: nil private key")
	}
	if md == nil {
		md = core.SHA256()
	}
	return priv.key.DecryptOAEP(data, md)
}

// Match 判断私钥与另一密钥（公钥/私钥/证书公钥）是否匹配；k 为 nil 或底层为 nil 时返回 false。
// 判断本私钥的公钥分量是否与 other 的公钥分量相等。k 或 k.key 为 nil 时返回 false；
// 仅用于跨包（如证书与密钥配对），不属于稳定公共 API。
//
// Match reports whether the public component of this private key equals
// the public component of other. Returns false when k or k.key is nil.
// It is intended for cross-package use (e.g. certificate / key pairing)
// and is not part of the stable public API.
func (k *PrivateKey) Match(other *core.PKey) bool {
	if k == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(other)
}
