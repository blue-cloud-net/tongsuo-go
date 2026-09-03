// Package key 提供算法无关的统合密钥抽象与密钥管理能力。
//
// 本包定义密钥根接口 Key 以及对称密钥抽象（SymmetricKey、AESKey、SM4Key）。
// 非对称密钥接口（AsymmetricKey 等）、PEM 自动嗅探解析、密钥生命周期管理
// （Handle/Store）与 KDF 派生将随后续阶段加入。算法包（crypto/rsa、
// crypto/sm2、crypto/ecdsa 等）通过实现本包接口向调用方提供统一入口；本包
// 自身只依赖 internal/core 与 crypto/rand，绝不反向 import 任何算法包，从而
// 避免与算法包的接口实现形成循环依赖。
//
// Package key provides an algorithm-agnostic unified key abstraction and
// key-management capabilities.
//
// It defines the root Key interface together with the symmetric-key
// abstractions (SymmetricKey, AESKey, SM4Key). The asymmetric-key
// interfaces (AsymmetricKey and friends), automatic PEM sniffing/parsing,
// key-lifecycle management (Handle/Store) and KDF derivation are added in
// later stages. Algorithm packages (crypto/rsa, crypto/sm2, crypto/ecdsa,
// ...) implement these interfaces to expose a single entry point to
// callers; this package itself depends only on internal/core and
// crypto/rand and never imports any algorithm package in return, which
// avoids a dependency cycle with the algorithm packages implementing its
// interfaces.
package key

import (
	"errors"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Algorithm 标识密钥算法。
//
// Algorithm identifies the algorithm of a key.
type Algorithm string

// 支持的密钥算法。
//
// Supported key algorithms.
const (
	// AlgRSA 标识 RSA 非对称算法。
	//
	// AlgRSA identifies the RSA asymmetric algorithm.
	AlgRSA Algorithm = "RSA"
	// AlgSM2 标识 SM2 非对称算法（GM/T 0003）。
	//
	// AlgSM2 identifies the SM2 asymmetric algorithm (GM/T 0003).
	AlgSM2 Algorithm = "SM2"
	// AlgECDSA 标识 ECDSA 非对称算法。
	//
	// AlgECDSA identifies the ECDSA asymmetric algorithm.
	AlgECDSA Algorithm = "ECDSA"
	// AlgAES128 标识 AES-128 对称算法（16 字节密钥）。
	//
	// AlgAES128 identifies the AES-128 symmetric algorithm (16-byte key).
	AlgAES128 Algorithm = "AES-128"
	// AlgAES256 标识 AES-256 对称算法（32 字节密钥）。
	//
	// AlgAES256 identifies the AES-256 symmetric algorithm (32-byte key).
	AlgAES256 Algorithm = "AES-256"
	// AlgSM4 标识 SM4 对称算法（GB/T 32907，16 字节密钥）。
	//
	// AlgSM4 identifies the SM4 symmetric algorithm (GB/T 32907, 16-byte key).
	AlgSM4 Algorithm = "SM4"
)

// Key 是所有密钥的根接口。
//
// 任何密钥（对称或非对称）通过 Algorithm 报告算法、通过 Equal 比较相等性；
// 更丰富的操作由 SymmetricKey 与后续阶段的非对称接口扩展提供。
//
// Key is the root interface satisfied by every key.
//
// Any key (symmetric or asymmetric) reports its algorithm through
// Algorithm and compares for equality through Equal; richer operations are
// layered on by SymmetricKey and the asymmetric interfaces introduced in a
// later stage.
type Key interface {
	// Algorithm 返回密钥算法。
	//
	// Algorithm returns the algorithm of the key.
	Algorithm() Algorithm
	// Equal 报告 k 与 other 是否表示同一密钥。
	// other 为 nil、非同类密钥或内容不同时返回 false。
	//
	// Equal reports whether k and other denote the same key.
	// It returns false when other is nil, is not the same kind of key, or
	// holds different content.
	Equal(other Key) bool
}

// PEM 描述一段已解码的 PEM 内容。
//
// Type 为块类型（如 "PRIVATE KEY"、"PUBLIC KEY"、"SYMMETRIC KEY"）；
// Headers 为 PEM 头部键值对；Bytes 为 base64 解码后的载荷（通常为 DER）。
//
// PEM describes a decoded PEM block.
//
// Type is the block type (for example "PRIVATE KEY", "PUBLIC KEY" or
// "SYMMETRIC KEY"); Headers holds the PEM header key/value pairs; Bytes is
// the base64-decoded payload (usually DER).
type PEM struct {
	Type    string
	Headers map[string]string
	Bytes   []byte
}

// 本包定义的错误。
//
// Package-level sentinel errors.
var (
	// ErrUnknownAlgorithm 表示请求了未知或未注册的密钥算法。
	//
	// ErrUnknownAlgorithm reports that an unknown or unregistered key algorithm was requested.
	ErrUnknownAlgorithm = errors.New("key: unknown algorithm")
	// ErrUnsupported 表示底层实现不支持所请求的操作（如 SM2 私钥导出 PKCS#1）。
	//
	// ErrUnsupported reports that the underlying implementation does not support the requested operation.
	ErrUnsupported = errors.New("key: unsupported operation")
	// ErrClosed 表示密钥句柄关闭后仍被使用。
	//
	// ErrClosed reports use of a key handle after it has been closed.
	ErrClosed = errors.New("key: key closed")
	// ErrNotFound 表示在密钥存储中未找到指定 ID 的条目。
	//
	// ErrNotFound reports that no entry with the given ID exists in a key store.
	ErrNotFound = errors.New("key: not found")
)

// pkeyHolder 是持有底层 *core.PKey 的密钥所应满足的内部窄接口。
//
// 各算法包（crypto/rsa、crypto/sm2、crypto/ecdsa）的密钥类型均已导出 Key()
// 方法，故 key 包无需 import 这些算法包即可经该接口回收底层句柄；该接口为
// 内部约定，不属于稳定公共 API。
//
// pkeyHolder is the internal narrow interface satisfied by keys that own an
// underlying *core.PKey.
//
// Because every key type of the algorithm packages (crypto/rsa, crypto/sm2,
// crypto/ecdsa) already exports a Key() method, this package can reclaim
// the underlying handle through this interface without importing those
// packages. The interface is an internal convention and is not part of the
// stable public API.
type pkeyHolder interface {
	Key() *core.PKey
}

// Close 释放密钥持有的底层句柄（若有）。
//
// 对称密钥不持有原生句柄，传入时直接返回 nil。非对称密钥经内部窄接口
// pkeyHolder 取到底层 *core.PKey 后调用其幂等的 Close。k 为 nil、动态类型未
// 实现 pkeyHolder、或底层句柄为 nil 时均返回 nil；调用可重复进行且无副作用。
//
// Close releases the underlying handle held by the key, if any.
//
// Symmetric keys own no native handle and return nil immediately. For
// asymmetric keys it obtains the underlying *core.PKey through the internal
// pkeyHolder interface and invokes its idempotent Close. It returns nil for
// a nil k, for a dynamic type that does not implement pkeyHolder, or when
// the underlying handle is nil; the call is repeatable and side-effect free.
func Close(k Key) error {
	if k == nil {
		return nil
	}
	h, ok := k.(pkeyHolder)
	if !ok {
		return nil
	}
	p := h.Key()
	if p == nil {
		return nil
	}
	return p.Close()
}
