package key

import (
	"encoding/pem"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// LoadPrivateKeyPEM 从 PEM 加载非对称私钥（SM2 / RSA / ECDSA，自动识别）。
// 依次尝试未加密 PKCS#8（"-----BEGIN PRIVATE KEY-----"）与 RSA 传统 PKCS#1
// （"-----BEGIN RSA PRIVATE KEY-----"）块；加密私钥 PEM 请改用
// LoadPrivateKeyPEMEncrypted。返回实现 AsymmetricPrivateKey 的包装，调用方
// 使用完毕应经 key.Close 释放底层句柄。
//
// LoadPrivateKeyPEM loads an asymmetric private key (SM2 / RSA / ECDSA,
// auto-detected) from PEM data.
// It tries an unencrypted PKCS#8 block ("-----BEGIN PRIVATE KEY-----")
// first and falls back to a legacy RSA PKCS#1 block ("-----BEGIN RSA PRIVATE
// KEY-----"); for encrypted private-key PEM use LoadPrivateKeyPEMEncrypted.
// The returned wrapper implements AsymmetricPrivateKey; callers should
// release the underlying handle through key.Close when done.
func LoadPrivateKeyPEM(p []byte) (AsymmetricPrivateKey, error) {
	pk, err := core.LoadPrivateKeyPEM(p)
	if err == nil {
		return wrapPrivate(pk)
	}
	pk2, err2 := core.LoadPrivateKeyPKCS1PEM(p)
	if err2 != nil {
		return nil, err
	}
	return wrapPrivate(pk2)
}

// LoadPrivateKeyPEMEncrypted 从加密 PEM 加载非对称私钥。
// 支持加密 PKCS#8 与基于口令的传统 PEM 格式；口令错误或解密失败返回错误。
//
// LoadPrivateKeyPEMEncrypted loads an asymmetric private key from an
// encrypted PEM block.
// It supports encrypted PKCS#8 as well as passphrase-based legacy PEM
// formats; an incorrect passphrase or any decryption failure returns an
// error.
func LoadPrivateKeyPEMEncrypted(p []byte, pass string) (AsymmetricPrivateKey, error) {
	pk, err := core.LoadPrivateKeyPEMEncrypted(p, pass)
	if err != nil {
		return nil, err
	}
	return wrapPrivate(pk)
}

// LoadPublicKeyPEM 从 PEM 加载非对称公钥（SPKI，"-----BEGIN PUBLIC KEY-----"）。
// 返回实现 AsymmetricPublicKey 的包装；调用方使用完毕应经 key.Close 释放。
//
// LoadPublicKeyPEM loads an asymmetric public key from a SubjectPublicKeyInfo
// (SPKI) PEM block ("-----BEGIN PUBLIC KEY-----").
// The returned wrapper implements AsymmetricPublicKey; callers should
// release the underlying handle through key.Close when done.
func LoadPublicKeyPEM(p []byte) (AsymmetricPublicKey, error) {
	pk, err := core.LoadPublicKeyPEM(p)
	if err != nil {
		return nil, err
	}
	return wrapPublic(pk)
}

// ParsePEM 解码输入中的首个 PEM 块并返回其描述。
// 未找到有效 PEM 块时返回错误。不解析内容语义，仅描述块头与载荷。
//
// ParsePEM decodes the first PEM block in the input and returns its
// description.
// It errors when no valid PEM block is found. It does not interpret the
// payload semantics, only the block header and payload.
func ParsePEM(p []byte) (*PEM, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("key: no PEM block found")
	}
	return &PEM{Type: block.Type, Headers: block.Headers, Bytes: block.Bytes}, nil
}

// wrapPrivate 将算法无关的 *core.PKey 包装为带算法的 PrivateKey。
// 无法识别算法时关闭句柄并返回 ErrUnknownAlgorithm。
//
// wrapPrivate wraps an algorithm-agnostic *core.PKey into a PrivateKey
// carrying its algorithm. When the algorithm is unrecognised it closes the
// handle and returns ErrUnknownAlgorithm.
func wrapPrivate(pk *core.PKey) (AsymmetricPrivateKey, error) {
	alg, err := algorithmOf(pk)
	if err != nil {
		_ = pk.Close()
		return nil, err
	}
	return newPrivateKey(pk, alg), nil
}

// wrapPublic 将算法无关的 *core.PKey 包装为带算法的 PublicKey。
// 无法识别算法时关闭句柄并返回 ErrUnknownAlgorithm。
//
// wrapPublic wraps an algorithm-agnostic *core.PKey into a PublicKey
// carrying its algorithm. When the algorithm is unrecognised it closes the
// handle and returns ErrUnknownAlgorithm.
func wrapPublic(pk *core.PKey) (AsymmetricPublicKey, error) {
	alg, err := algorithmOf(pk)
	if err != nil {
		_ = pk.Close()
		return nil, err
	}
	return newPublicKey(pk, alg), nil
}
