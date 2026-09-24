package asym

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PSSSaltLenDigest / PSSSaltLenAuto / PSSSaltLenMax 沿用 OpenSSL EVP_PKEY_CTX_set_rsa_pss_saltlen 约定。
//
// PSS salt-length sentinel constants, matching the OpenSSL
// EVP_PKEY_CTX_set_rsa_pss_saltlen convention.
const (
	PSSSaltLenDigest = -1
	PSSSaltLenAuto   = -2
	PSSSaltLenMax    = -3
)

// rsaPrivateKey 是 RSA 私钥的具体类型（非导出）。
//
// rsaPrivateKey is the concrete (unexported) type for RSA private keys.
type rsaPrivateKey struct {
	key *core.PKey
}

// rsaPublicKey 是 RSA 公钥的具体类型（非导出）。
//
// rsaPublicKey is the concrete (unexported) type for RSA public keys.
type rsaPublicKey struct {
	key *core.PKey
}

// Algorithm 实现 Key 接口。
func (k *rsaPrivateKey) Algorithm() Algorithm { return AlgRSA }

// Algorithm 实现 Key 接口。
func (k *rsaPublicKey) Algorithm() Algorithm { return AlgRSA }

// corePKey 实现 Key 接口。
func (k *rsaPrivateKey) corePKey() *core.PKey { return k.key }

// corePKey 实现 Key 接口。
func (k *rsaPublicKey) corePKey() *core.PKey { return k.key }

// Public 返回配对的公钥（共享底层 core.PKey）。
func (k *rsaPrivateKey) Public() PublicKey {
	return &rsaPublicKey{key: k.key}
}

// MarshalPrivateKeyPEM 导出为 PKCS#8 PEM。
func (k *rsaPrivateKey) MarshalPrivateKeyPEM() ([]byte, error) {
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalRSAPrivateKeyPKCS1PEM 导出 RSA 私钥为传统 PKCS#1 PEM。
//
// MarshalRSAPrivateKeyPKCS1PEM encodes an RSA private key using the
// legacy PKCS#1 PEM format. New protocols should prefer MarshalPrivateKeyPEM.
func MarshalRSAPrivateKeyPKCS1PEM(priv PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: PKCS1PEM requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.MarshalPrivateKeyPKCS1PEM()
}

// MarshalRSAPrivateKeyEncryptedPEM 用口令加密导出 RSA 私钥（AES-256-CBC + PBKDF2）。
//
// MarshalRSAPrivateKeyEncryptedPEM encodes an RSA private key as an
// encrypted PEM block (AES-256-CBC + PBKDF2) using the given passphrase.
func MarshalRSAPrivateKeyEncryptedPEM(priv PrivateKey, pass string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: EncryptedPEM requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.MarshalEncryptedPEM(pass)
}

// MarshalRSAPrivateKeyEncryptedPEMWithCipher 用指定 cipher 加密导出 RSA 私钥。
// cipher 取 OpenSSL 通用名（如 "aes-128-cbc"、"aes-256-cbc"、"des-ede3-cbc"）；
// cipher == "" 与 MarshalRSAPrivateKeyEncryptedPEM 等价。
func MarshalRSAPrivateKeyEncryptedPEMWithCipher(priv PrivateKey, cipher, pass string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: EncryptedPEMWithCipher requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.MarshalEncryptedPEMWithCipher(cipher, pass)
}

// MarshalPublicKeyPEM 实现 PublicKey 接口。
func (k *rsaPublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
}

// RSAParams 返回 RSA 私钥参数。
//
// RSAParams returns the RSA parameters of the private key.
func RSAParams(priv PrivateKey) (*core.KeyParams, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: Params requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.Params(), nil
}

// RSAPublicParams 返回 RSA 公钥参数。
func RSAPublicParams(pub PublicKey) (*core.KeyParams, error) {
	if pub == nil {
		return nil, fmt.Errorf("asym: rsa: nil public key")
	}
	k, ok := pub.(*rsaPublicKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: Params requires an RSA key, got %s", pub.Algorithm())
	}
	return k.key.Params(), nil
}

// RSAMatch 判断本私钥公钥分量是否与 other 一致；nil-safe。
//
// RSAMatch reports whether the public component of priv equals other's.
func RSAMatch(priv PrivateKey, other *core.PKey) (bool, error) {
	if priv == nil {
		return false, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return false, fmt.Errorf("asym: rsa: Match requires an RSA key, got %s", priv.Algorithm())
	}
	if k.key == nil {
		return false, nil
	}
	return k.key.PublicEqual(other), nil
}

// GenerateRSA 生成 bits 位 RSA 密钥对。bits 须 >= 1024。
//
// GenerateRSA generates an RSA key pair of the given bit size.
// bits must be at least 1024.
func GenerateRSA(bits int) (PrivateKey, error) {
	if bits < 1024 {
		return nil, fmt.Errorf("asym: rsa: key size too small: %d", bits)
	}
	k, err := core.GenerateRSAKey(bits)
	if err != nil {
		return nil, err
	}
	return &rsaPrivateKey{key: k}, nil
}

// LoadPrivateKeyPEM 从 PEM 加载 RSA 私钥（PKCS#8 或 PKCS#1）。
// 解析非加密 PEM 块：PKCS#8（"-----BEGIN PRIVATE KEY-----"）优先，
// 失败后再尝试 PKCS#1（"-----BEGIN RSA PRIVATE KEY-----"）。
// 加载后会校验算法确为 RSA。
//
// LoadPrivateKeyPEM parses an unencrypted PEM block carrying either a
// PKCS#8 or a legacy PKCS#1 RSA private key. PKCS#8 is tried first;
// on PKCS#8 failure PKCS#1 is attempted. The underlying algorithm is
// verified to be RSA.
func LoadPrivateKeyPEM(pem []byte) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEM(pem)
	if err == nil {
		if !isRSAKey(k) {
			alg := k.Algorithm()
			k.Close()
			return nil, fmt.Errorf("asym: rsa: PEM private key is not RSA (got %s)", alg)
		}
		return &rsaPrivateKey{key: k}, nil
	}
	k2, err2 := core.LoadPrivateKeyPKCS1PEM(pem)
	if err2 != nil {
		return nil, fmt.Errorf("asym: rsa: LoadPrivateKeyPEM: pkcs8: %v; pkcs1: %v", err, err2)
	}
	if !isRSAKey(k2) {
		alg := k2.Algorithm()
		k2.Close()
		return nil, fmt.Errorf("asym: rsa: PEM private key is not RSA (got %s)", alg)
	}
	return &rsaPrivateKey{key: k2}, nil
}

// LoadEncryptedPrivateKeyPEM 从加密 PEM（"BEGIN ENCRYPTED PRIVATE KEY"）加载 RSA 私钥。
// pass 为口令；口令错误或算法非 RSA 时返回错误。
//
// LoadEncryptedPrivateKeyPEM parses an encrypted PEM block (AES-256-CBC +
// PBKDF2) using the given passphrase.
func LoadEncryptedPrivateKeyPEM(pem []byte, pass string) (PrivateKey, error) {
	k, err := core.LoadPrivateKeyPEMEncrypted(pem, pass)
	if err != nil {
		return nil, err
	}
	if !isRSAKey(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("asym: rsa: encrypted PEM private key is not RSA (got %s)", alg)
	}
	return &rsaPrivateKey{key: k}, nil
}

// LoadPublicKeyPEM 从 PEM（SubjectPublicKeyInfo）加载 RSA 公钥。
// 算法非 RSA 时返回错误。
//
// LoadPublicKeyPEM parses a SPKI PEM block ("-----BEGIN PUBLIC KEY-----")
// carrying an RSA public key.
func LoadPublicKeyPEM(pem []byte) (PublicKey, error) {
	k, err := core.LoadPublicKeyPEM(pem)
	if err != nil {
		return nil, err
	}
	if !isRSAKey(k) {
		alg := k.Algorithm()
		k.Close()
		return nil, fmt.Errorf("asym: rsa: PEM public key is not RSA (got %s)", alg)
	}
	return &rsaPublicKey{key: k}, nil
}

// ChangePassword 读取旧口令加密的 PEM 并导出为新口令加密。
//
// ChangePassword decrypts an encrypted private-key PEM with oldPass and
// returns a freshly encrypted PEM under newPass.
func ChangePassword(pemBytes []byte, oldPass, newPass string) ([]byte, error) {
	return core.ChangePrivateKeyPassword(pemBytes, oldPass, newPass)
}

// isRSAKey 报告 *core.PKey 的底层算法是否为 RSA。
func isRSAKey(k *core.PKey) bool {
	return k != nil && k.Algorithm() == "RSA"
}

// digestForRSAHash 按名称解析 RSA 签名摘要；空串默认 SHA-256。
func digestForRSAHash(hash string) (*core.Digest, error) {
	switch hash {
	case "", "sha256":
		return core.SHA256(), nil
	case "sha1":
		return core.SHA1(), nil
	case "sha224":
		return core.SHA224(), nil
	case "sha384":
		return core.SHA384(), nil
	case "sha512":
		return core.SHA512(), nil
	default:
		return nil, fmt.Errorf("asym: rsa: unsupported hash %q", hash)
	}
}

// SignPKCS1v15 使用 RSA-PKCS#1 v1.5（RFC 8017）对 data 签名，摘要由 digest 指定。
// digest 取 "sha1" / "sha224" / "sha256" / "sha384" / "sha512"，空串默认 SHA-256。
//
// SignPKCS1v15 signs data with RSA-PKCS#1 v1.5 (RFC 8017) using the
// digest selected by digest.
func SignPKCS1v15(priv PrivateKey, data []byte, digest string) ([]byte, error) {
	md, err := digestForRSAHash(digest)
	if err != nil {
		return nil, err
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: SignPKCS1v15 requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.SignDigest(data, md)
}

// VerifyPKCS1v15 使用 RSA-PKCS#1 v1.5 验签。
// digest 取值同 SignPKCS1v15。
//
// VerifyPKCS1v15 checks an RSA-PKCS#1 v1.5 signature.
func VerifyPKCS1v15(pub PublicKey, data, sig []byte, digest string) error {
	md, err := digestForRSAHash(digest)
	if err != nil {
		return err
	}
	k, ok := pub.(*rsaPublicKey)
	if !ok {
		return fmt.Errorf("asym: rsa: VerifyPKCS1v15 requires an RSA key, got %s", pub.Algorithm())
	}
	return k.key.VerifyDigest(data, sig, md)
}

// SignPSS 使用 RSA-PSS 签名。saltLen 取 PSS* 常量或正整数；digest 取值同 SignPKCS1v15。
//
// SignPSS signs data with RSA-PSS (RFC 8017). saltLen accepts the PSS*
// sentinels or a positive byte count.
func SignPSS(priv PrivateKey, data []byte, saltLen int, digest string) ([]byte, error) {
	md, err := digestForRSAHash(digest)
	if err != nil {
		return nil, err
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: SignPSS requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.SignDigestPSS(data, md, saltLen)
}

// VerifyPSS 使用 RSA-PSS 验签。hash 与 saltLen 必须与签名时一致。
//
// VerifyPSS checks an RSA-PSS signature.
func VerifyPSS(pub PublicKey, data, sig []byte, saltLen int, digest string) error {
	md, err := digestForRSAHash(digest)
	if err != nil {
		return err
	}
	k, ok := pub.(*rsaPublicKey)
	if !ok {
		return fmt.Errorf("asym: rsa: VerifyPSS requires an RSA key, got %s", pub.Algorithm())
	}
	return k.key.VerifyDigestPSS(data, sig, md, saltLen)
}

// EncryptPKCS1v15 使用 RSA-PKCS#1 v1.5 填充加密（明文须严格短于模数）。
// 存在 Bleichenbacher padding oracle 漏洞，新协议推荐 EncryptOAEP。
//
// EncryptPKCS1v15 encrypts data with RSA-PKCS#1 v1.5 padding.
// Has known padding-oracle vulnerabilities; new protocols should use
// EncryptOAEP.
func EncryptPKCS1v15(pub PublicKey, data []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("asym: rsa: nil public key")
	}
	k, ok := pub.(*rsaPublicKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: EncryptPKCS1v15 requires an RSA key, got %s", pub.Algorithm())
	}
	return k.key.EncryptPKCS1v15(data)
}

// DecryptPKCS1v15 使用 RSA-PKCS#1 v1.5 填充解密。
// 任何解密失败须上报错误；上层需做等时常时间处理。
//
// DecryptPKCS1v15 decrypts data with RSA-PKCS#1 v1.5 padding.
func DecryptPKCS1v15(priv PrivateKey, data []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: DecryptPKCS1v15 requires an RSA key, got %s", priv.Algorithm())
	}
	return k.key.DecryptPKCS1v15(data)
}

// EncryptOAEP 使用 RSA-OAEP 填充加密。digest 同时选择 OAEP 与 MGF1 摘要，
// 空串默认 SHA-256；DecryptOAEP 须使用相同 digest。
//
// EncryptOAEP encrypts data with RSA-OAEP padding. digest selects
// both the OAEP encoding hash and the MGF1 hash (empty defaults to
// SHA-256). DecryptOAEP must use the same digest.
func EncryptOAEP(pub PublicKey, data []byte, digest string) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("asym: rsa: nil public key")
	}
	k, ok := pub.(*rsaPublicKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: EncryptOAEP requires an RSA key, got %s", pub.Algorithm())
	}
	md, err := digestForRSAHash(digest)
	if err != nil {
		return nil, err
	}
	return k.key.EncryptOAEP(data, md)
}

// DecryptOAEP 使用 RSA-OAEP 填充解密。
func DecryptOAEP(priv PrivateKey, data []byte, digest string) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("asym: rsa: nil private key")
	}
	k, ok := priv.(*rsaPrivateKey)
	if !ok {
		return nil, fmt.Errorf("asym: rsa: DecryptOAEP requires an RSA key, got %s", priv.Algorithm())
	}
	md, err := digestForRSAHash(digest)
	if err != nil {
		return nil, err
	}
	return k.key.DecryptOAEP(data, md)
}
