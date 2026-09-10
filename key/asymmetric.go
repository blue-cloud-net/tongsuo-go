package key

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// AsymmetricKey 表示一个同时携带私钥与公钥的非对称密钥对象。
//
// key.PrivateKey 实现本接口（Private 返回其自身，Public 返回共享底层句柄的
// 公钥视图）。仅持有公钥的解析结果不满足本接口，但满足 AsymmetricPublicKey。
//
// AsymmetricKey represents an asymmetric key object carrying both a private
// and a public component.
//
// key.PrivateKey implements this interface (Private returns the receiver
// itself and Public returns a public view sharing the underlying handle).
// A parse result that holds only a public key does not satisfy this
// interface, but does satisfy AsymmetricPublicKey.
type AsymmetricKey interface {
	Key
	CoreKey
	// Private 返回该密钥对象的私钥部分。
	//
	// Private returns the private part of the key object.
	Private() AsymmetricPrivateKey
	// Public 返回该密钥对象的公钥部分。
	//
	// Public returns the public part of the key object.
	Public() AsymmetricPublicKey
}

// AsymmetricPrivateKey 表示非对称私钥（SM2 / RSA / ECDSA）。
//
// 提供 PKCS#8（Marshal）、加密 PKCS#8（MarshalEncrypted）与 RSA 传统 PKCS#1
// （MarshalPKCS1）三种导出；非 RSA 算法调用 MarshalPKCS1 返回 ErrUnsupported。
// 接口不含 Close，底层句柄统一由 key.Close 释放。
//
// AsymmetricPrivateKey represents an asymmetric private key
// (SM2 / RSA / ECDSA).
//
// It exports the key as PKCS#8 (Marshal), encrypted PKCS#8
// (MarshalEncrypted) and, for RSA, legacy PKCS#1 (MarshalPKCS1); calling
// MarshalPKCS1 on a non-RSA key returns ErrUnsupported. The interface has
// no Close; the underlying handle is released uniformly through key.Close.
type AsymmetricPrivateKey interface {
	Key
	CoreKey
	// Public 返回与该私钥配对的公钥（共享底层句柄）。
	//
	// Public returns the public key paired with this private key,
	// sharing the underlying handle.
	Public() AsymmetricPublicKey
	// Marshal 将私钥导出为 PKCS#8 PEM 块（"-----BEGIN PRIVATE KEY-----"）。
	//
	// Marshal serializes the private key as a PKCS#8 PEM block
	// ("-----BEGIN PRIVATE KEY-----").
	Marshal() ([]byte, error)
	// MarshalEncrypted 用口令将私钥导出为加密 PEM 块（AES-256-CBC + PBKDF2）。
	//
	// MarshalEncrypted serializes the private key as an encrypted PEM
	// block (AES-256-CBC + PBKDF2) under the given passphrase.
	MarshalEncrypted(pass string) ([]byte, error)
	// MarshalPKCS1 将 RSA 私钥导出为传统 PKCS#1 PEM；非 RSA 返回 ErrUnsupported。
	//
	// MarshalPKCS1 serializes an RSA private key as the legacy PKCS#1 PEM
	// format; non-RSA keys return ErrUnsupported.
	MarshalPKCS1() ([]byte, error)
}

// AsymmetricPublicKey 表示非对称公钥（SM2 / RSA / ECDSA）。
//
// 以 SubjectPublicKeyInfo（SPKI）PEM 块导出。接口不含 Close。
//
// AsymmetricPublicKey represents an asymmetric public key
// (SM2 / RSA / ECDSA).
//
// It exports the key as a SubjectPublicKeyInfo (SPKI) PEM block. The
// interface has no Close.
type AsymmetricPublicKey interface {
	Key
	CoreKey
	// Marshal 将公钥导出为 SPKI PEM 块（"-----BEGIN PUBLIC KEY-----"）。
	//
	// Marshal serializes the public key as an SPKI PEM block
	// ("-----BEGIN PUBLIC KEY-----").
	Marshal() ([]byte, error)
}

// CoreKey 表示持有一个底层核心密钥句柄（*core.PKey）的密钥。
//
// key.PrivateKey 与 key.PublicKey,以及 crypto/{rsa,sm2,ecdsa} 的私钥/公钥类型
// 均实现本接口;key 的 AsymmetricKey / AsymmetricPrivateKey / AsymmetricPublicKey
// 三个接口亦内嵌本接口。它是消费方（x509、jwk、pkcs12 等）接收"任意算法、私钥或
// 公钥"时使用的窄载体接口——接口值可直接传给这些消费方,经 Key() 取底层句柄后再
// 做原生操作,避免依赖具体类型。方法返回 *core.PKey;外部调用方可以透传该句柄而不必
// 命名其类型（internal/core 不可被库外 import）。
//
// CoreKey represents a key that owns an underlying core key handle
// (*core.PKey).
//
// Both key.PrivateKey and key.PublicKey, as well as every private/public
// key type of crypto/{rsa,sm2,ecdsa}, implement this interface, and the
// AsymmetricKey / AsymmetricPrivateKey / AsymmetricPublicKey interfaces embed
// it. It is the narrow carrier interface consumers (x509, jwk, pkcs12, ...)
// use to accept keys of any algorithm and visibility — interface values can
// be handed straight to those consumers, which retrieve the underlying
// handle through Key() before performing native operations, without
// depending on a concrete type. The method returns *core.PKey; external
// callers may pass the handle along without having to name its type
// (internal/core cannot be imported outside the module).
type CoreKey interface {
	Key() *core.PKey
}

// PrivateKey 是 key 包自有的非对称私钥包装，持有 *core.PKey 句柄与算法标识。
//
// 通过 key 包级构造器（GenerateRSAKey / GenerateSM2Key / GenerateECKey）或解析
// 函数（LoadPrivateKeyPEM 等）获得；实现 AsymmetricPrivateKey 与 AsymmetricKey
// 接口。与 crypto/{rsa,sm2,ecdsa} 包的类型是并存的两套表示——它们都包装同一个
// *core.PKey，可经各自的 Key() 方法互转，本类型面向"统合使用"场景。
//
// PrivateKey is the package's own asymmetric private-key wrapper, holding a
// *core.PKey handle together with an algorithm identifier.
//
// Obtain one from the package-level constructors (GenerateRSAKey /
// GenerateSM2Key / GenerateECKey) or parse helpers (LoadPrivateKeyPEM and
// friends); it implements the AsymmetricPrivateKey and AsymmetricKey
// interfaces. It coexists with the crypto/{rsa,sm2,ecdsa} package types as a
// second representation — both wrap the same *core.PKey and interconvert
// through their Key() methods. This type targets unified-usage scenarios.
type PrivateKey struct {
	key *core.PKey
	alg Algorithm
}

// PublicKey 是 key 包自有的非对称公钥包装，持有 *core.PKey 句柄与算法标识。
//
// 实现 AsymmetricPublicKey 接口。私钥的 Public() 返回与私钥共享同一底层句柄的
// PublicKey；由 SPKI 解析得到的 PublicKey 只含公钥分量。请通过 key.Close 释放。
//
// PublicKey is the package's own asymmetric public-key wrapper, holding a
// *core.PKey handle together with an algorithm identifier.
//
// It implements the AsymmetricPublicKey interface. The Public() of a private
// key returns a PublicKey sharing the same underlying handle; a PublicKey
// parsed from SPKI carries only the public part. Release it via key.Close.
type PublicKey struct {
	key *core.PKey
	alg Algorithm
}

// newPrivateKey 用底层句柄与算法构造私钥包装。
//
// newPrivateKey wraps a core.PKey handle and algorithm into a PrivateKey.
func newPrivateKey(p *core.PKey, alg Algorithm) *PrivateKey {
	return &PrivateKey{key: p, alg: alg}
}

// newPublicKey 用底层句柄与算法构造公钥包装。
//
// newPublicKey wraps a core.PKey handle and algorithm into a PublicKey.
func newPublicKey(p *core.PKey, alg Algorithm) *PublicKey {
	return &PublicKey{key: p, alg: alg}
}

// Algorithm 返回私钥算法。
//
// Algorithm returns the algorithm of the private key.
func (k *PrivateKey) Algorithm() Algorithm {
	if k == nil {
		return ""
	}
	return k.alg
}

// Key 返回底层核心密钥对象（供内部跨包与 key.Close 使用）。
// 与 crypto/rsa 等算法包保持一致；不属于稳定公共 API。
//
// Key returns the underlying *core.PKey. It is intended for internal
// cross-package use and for key.Close, mirroring the crypto/rsa packages;
// it is not part of the stable public API.
func (k *PrivateKey) Key() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// Public 返回与该私钥配对的公钥视图（共享底层句柄）。
// 关闭私钥后公钥视图同样失效；两侧的 Close 均为幂等。
//
// Public returns a public view paired with this private key, sharing the
// underlying handle. Closing the private key invalidates the view as well;
// Close on either side is idempotent.
func (k *PrivateKey) Public() AsymmetricPublicKey {
	if k == nil {
		return nil
	}
	return newPublicKey(k.key, k.alg)
}

// Private 返回私钥部分（即接收者自身），使 PrivateKey 满足 AsymmetricKey。
//
// Private returns the private part of the key (the receiver itself),
// making PrivateKey satisfy AsymmetricKey.
func (k *PrivateKey) Private() AsymmetricPrivateKey {
	return k
}

// Equal 报告 k 与 other 是否表示同一私钥。
// 要求 other 也持有底层 *core.PKey 且底层密钥完整相等；否则返回 false。
//
// Equal reports whether k and other denote the same private key.
// other must hold an underlying *core.PKey and the full keys must be
// equal; otherwise it returns false.
func (k *PrivateKey) Equal(other Key) bool {
	if k == nil || other == nil {
		return false
	}
	o, ok := other.(pkeyHolder)
	if !ok || o.Key() == nil || k.key == nil {
		return false
	}
	return k.key.Equal(o.Key())
}

// Marshal 将私钥导出为 PKCS#8 PEM 块。
// 底层失败（含句柄已关闭）时返回包装错误。
//
// Marshal serializes the private key as a PKCS#8 PEM block.
// Underlying failures (including a closed handle) return an error.
func (k *PrivateKey) Marshal() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("key: nil private key")
	}
	return k.key.MarshalPrivateKeyPEM()
}

// MarshalEncrypted 用口令将私钥导出为加密 PEM 块（AES-256-CBC + PBKDF2）。
// 空口令或底层失败返回错误。
//
// MarshalEncrypted serializes the private key as an encrypted PEM block
// (AES-256-CBC + PBKDF2) under the given passphrase. An empty passphrase
// or any underlying failure returns an error.
func (k *PrivateKey) MarshalEncrypted(pass string) ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("key: nil private key")
	}
	return k.key.MarshalEncryptedPEM(pass)
}

// MarshalPKCS1 将 RSA 私钥导出为传统 PKCS#1 PEM 块。
// 非 RSA 私钥（SM2/ECDSA）返回 ErrUnsupported；底层失败返回错误。
//
// MarshalPKCS1 serializes an RSA private key as the legacy PKCS#1 PEM
// block. Non-RSA keys (SM2/ECDSA) return ErrUnsupported; underlying
// failures return an error.
func (k *PrivateKey) MarshalPKCS1() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("key: nil private key")
	}
	if k.alg != AlgRSA {
		return nil, ErrUnsupported
	}
	return k.key.MarshalPrivateKeyPKCS1PEM()
}

// Algorithm 返回公钥算法。
//
// Algorithm returns the algorithm of the public key.
func (k *PublicKey) Algorithm() Algorithm {
	if k == nil {
		return ""
	}
	return k.alg
}

// Key 返回底层核心密钥对象（供内部跨包与 key.Close 使用）。
// 不属于稳定公共 API。
//
// Key returns the underlying *core.PKey. It is intended for internal
// cross-package use and for key.Close; it is not part of the stable
// public API.
func (k *PublicKey) Key() *core.PKey {
	if k == nil {
		return nil
	}
	return k.key
}

// Equal 报告 k 与 other 是否表示同一公钥。
// 要求 other 也持有底层 *core.PKey 且公钥分量相等；否则返回 false。
//
// Equal reports whether k and other denote the same public key.
// other must hold an underlying *core.PKey whose public components are
// equal; otherwise it returns false.
func (k *PublicKey) Equal(other Key) bool {
	if k == nil || other == nil {
		return false
	}
	o, ok := other.(pkeyHolder)
	if !ok || o.Key() == nil || k.key == nil {
		return false
	}
	return k.key.PublicEqual(o.Key())
}

// Marshal 将公钥导出为 SPKI PEM 块。
// 底层失败（含句柄已关闭）时返回错误。
//
// Marshal serializes the public key as an SPKI PEM block.
// Underlying failures (including a closed handle) return an error.
func (k *PublicKey) Marshal() ([]byte, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("key: nil public key")
	}
	return k.key.MarshalPublicKeyPEM()
}

// algorithmOf 依据底层 core.PKey 的算法名推导 Algorithm。
// 未知算法返回包装 ErrUnknownAlgorithm 的错误；当前支持的算法：RSA / SM2 / ECDSA / ED25519 / ED448 / X25519。
//
// algorithmOf derives an Algorithm from the underlying core.PKey algorithm
// name. Unknown algorithms return an error wrapping ErrUnknownAlgorithm;
// supported algorithms are RSA, SM2, ECDSA, ED25519, ED448 and X25519.
func algorithmOf(p *core.PKey) (Algorithm, error) {
	if p == nil {
		return "", ErrUnknownAlgorithm
	}
	switch p.Algorithm() {
	case "RSA":
		return AlgRSA, nil
	case "SM2":
		return AlgSM2, nil
	case "EC", "ECDSA":
		return AlgECDSA, nil
	case "ED25519":
		return AlgED25519, nil
	case "ED448":
		return AlgED448, nil
	case "X25519":
		return AlgX25519, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnknownAlgorithm, p.Algorithm())
	}
}
