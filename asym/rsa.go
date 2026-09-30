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

// MarshalPublicKeyPEM 实现 PublicKey 接口。
func (k *rsaPublicKey) MarshalPublicKeyPEM() ([]byte, error) {
	return k.key.MarshalPublicKeyPEM()
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
