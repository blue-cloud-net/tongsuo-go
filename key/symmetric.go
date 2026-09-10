package key

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

// SymmetricKey 表示对称密钥。
//
// 对称密钥（AES、SM4）以原始字节为密钥材料。具体包装类型 AESKey 与 SM4Key
// 实现本接口：Bytes 返回原始密钥字节的拷贝，Size 返回字节长度，Marshal 以
// 自定义 PEM 块（Type = "SYMMETRIC KEY"）导出。对称密钥不持有原生句柄，
// 无需 Close。
//
// SymmetricKey represents a symmetric key.
//
// Symmetric keys (AES, SM4) use raw bytes as their key material. The
// concrete wrapper types AESKey and SM4Key implement this interface:
// Bytes returns a copy of the raw key bytes, Size reports the length in
// bytes, and Marshal exports the key as a custom PEM block
// (Type = "SYMMETRIC KEY"). Symmetric keys own no native handle and need
// no Close.
type SymmetricKey interface {
	Key
	// Bytes 返回密钥原始字节的拷贝。
	// 修改返回值不影响密钥内部状态。
	//
	// Bytes returns a copy of the raw key bytes.
	// Mutating the returned slice does not affect the key's internal state.
	Bytes() []byte
	// Size 返回密钥长度（字节）。
	//
	// Size returns the key length in bytes.
	Size() int
	// Marshal 将密钥导出为 PEM 块（Type = "SYMMETRIC KEY"）。
	// 导出块携带 Algorithm 头部以标识具体算法，供 ParseSymmetricKey 还原。
	//
	// Marshal serializes the key as a PEM block (Type = "SYMMETRIC KEY").
	// The block carries an Algorithm header so that ParseSymmetricKey can
	// restore the exact algorithm.
	Marshal() ([]byte, error)
}

// symmetricPEMType 为对称密钥 PEM 块类型。
//
// symmetricPEMType is the PEM block type used for symmetric keys.
const symmetricPEMType = "SYMMETRIC KEY"

// AESKey 表示 AES 对称密钥（AES-128 或 AES-256）。
//
// 通过 NewAESKey 构造并校验长度（16 或 32 字节），亦可由 GenerateSymmetricKey
// 生成随机密钥。底层不持有原生句柄，无需 Close。
//
// AESKey represents an AES symmetric key (AES-128 or AES-256).
//
// Construct one via NewAESKey, which validates the length (16 or 32 bytes),
// or obtain a fresh random key from GenerateSymmetricKey. It owns no native
// handle and needs no Close.
type AESKey struct {
	alg Algorithm
	raw []byte
}

// NewAESKey 用给定的原始字节构造 AES 密钥。
// raw 长度必须为 16（AES-128）或 32（AES-256），否则返回错误。
// 构造时会拷贝 raw，调用方后续修改 raw 不影响密钥。
//
// NewAESKey wraps raw as an AES key.
// raw must be 16 (AES-128) or 32 (AES-256) bytes long, otherwise an error
// is returned. The input is copied, so later mutation of raw does not
// affect the key.
func NewAESKey(raw []byte) (*AESKey, error) {
	var alg Algorithm
	switch len(raw) {
	case 16:
		alg = AlgAES128
	case 32:
		alg = AlgAES256
	default:
		return nil, fmt.Errorf("key: invalid AES key size %d, want 16 or 32", len(raw))
	}
	return &AESKey{alg: alg, raw: append([]byte(nil), raw...)}, nil
}

// Algorithm 返回 AES 密钥算法（AlgAES128 或 AlgAES256）。
//
// Algorithm returns the AES key algorithm (AlgAES128 or AlgAES256).
func (k *AESKey) Algorithm() Algorithm {
	if k == nil {
		return ""
	}
	return k.alg
}

// Size 返回密钥长度（字节），为 16（AES-128）或 32（AES-256）。
//
// Size returns the key length in bytes: 16 (AES-128) or 32 (AES-256).
func (k *AESKey) Size() int {
	if k == nil {
		return 0
	}
	return len(k.raw)
}

// Bytes 返回密钥原始字节的拷贝。
// 修改返回值不影响密钥内部状态。
//
// Bytes returns a copy of the raw key bytes.
// Mutating the returned slice does not affect the key's internal state.
func (k *AESKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.raw...)
}

// Equal 报告 k 与 other 是否表示同一 AES 密钥。
// 要求 other 为同算法对称密钥且原始字节相等；否则返回 false。
//
// Equal reports whether k and other denote the same AES key.
// Both must be symmetric keys of the same algorithm with equal raw bytes,
// otherwise it returns false.
func (k *AESKey) Equal(other Key) bool {
	if k == nil || other == nil {
		return false
	}
	o, ok := other.(SymmetricKey)
	if !ok || o.Algorithm() != k.alg {
		return false
	}
	return bytes.Equal(k.raw, o.Bytes())
}

// Marshal 将密钥导出为 PEM 块（Type = "SYMMETRIC KEY"）。
// 块头携带 Algorithm 以标识 AES-128 / AES-256；编码过程不失败，恒返回 nil 错误。
//
// Marshal serializes the key as a PEM block (Type = "SYMMETRIC KEY").
// The Algorithm header records AES-128 / AES-256; encoding cannot fail and
// the error return is always nil.
func (k *AESKey) Marshal() ([]byte, error) {
	return marshalSymmetric(k.alg, k.raw)
}

// SM4Key 表示 SM4 对称密钥（GB/T 32907，16 字节密钥）。
//
// 通过 NewSM4Key 构造并校验长度（16 字节），亦可由 GenerateSymmetricKey 生成
// 随机密钥。底层不持有原生句柄，无需 Close。
//
// SM4Key represents an SM4 symmetric key (GB/T 32907, 16-byte key).
//
// Construct one via NewSM4Key, which validates the length (16 bytes), or
// obtain a fresh random key from GenerateSymmetricKey. It owns no native
// handle and needs no Close.
type SM4Key struct {
	raw []byte
}

// NewSM4Key 用给定的原始字节构造 SM4 密钥。
// raw 长度必须为 16 字节，否则返回错误。构造时会拷贝 raw。
//
// NewSM4Key wraps raw as an SM4 key.
// raw must be 16 bytes long, otherwise an error is returned. The input is
// copied on construction.
func NewSM4Key(raw []byte) (*SM4Key, error) {
	if len(raw) != 16 {
		return nil, fmt.Errorf("key: invalid SM4 key size %d, want 16", len(raw))
	}
	return &SM4Key{raw: append([]byte(nil), raw...)}, nil
}

// Algorithm 返回 SM4 密钥算法（恒为 AlgSM4）。
//
// Algorithm returns the SM4 key algorithm (always AlgSM4).
func (k *SM4Key) Algorithm() Algorithm {
	if k == nil {
		return ""
	}
	return AlgSM4
}

// Size 返回密钥长度（字节），恒为 16。
//
// Size returns the key length in bytes, always 16.
func (k *SM4Key) Size() int {
	if k == nil {
		return 0
	}
	return len(k.raw)
}

// Bytes 返回密钥原始字节的拷贝。
// 修改返回值不影响密钥内部状态。
//
// Bytes returns a copy of the raw key bytes.
// Mutating the returned slice does not affect the key's internal state.
func (k *SM4Key) Bytes() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.raw...)
}

// Equal 报告 k 与 other 是否表示同一 SM4 密钥。
// 要求 other 为 AlgSM4 对称密钥且原始字节相等；否则返回 false。
//
// Equal reports whether k and other denote the same SM4 key.
// other must be an AlgSM4 symmetric key with equal raw bytes, otherwise it
// returns false.
func (k *SM4Key) Equal(other Key) bool {
	if k == nil || other == nil {
		return false
	}
	o, ok := other.(SymmetricKey)
	if !ok || o.Algorithm() != AlgSM4 {
		return false
	}
	return bytes.Equal(k.raw, o.Bytes())
}

// Marshal 将密钥导出为 PEM 块（Type = "SYMMETRIC KEY"）。
// 块头携带 Algorithm 以标识 SM4；编码过程不失败，恒返回 nil 错误。
//
// Marshal serializes the key as a PEM block (Type = "SYMMETRIC KEY").
// The Algorithm header records SM4; encoding cannot fail and the error
// return is always nil.
func (k *SM4Key) Marshal() ([]byte, error) {
	return marshalSymmetric(AlgSM4, k.raw)
}

// marshalSymmetric 将对称密钥编码为携带 Algorithm 头的 PEM 块。
//
// marshalSymmetric encodes a symmetric key as a PEM block carrying an
// Algorithm header. Encoding cannot fail and the error return is always nil.
func marshalSymmetric(alg Algorithm, raw []byte) ([]byte, error) {
	block := &pem.Block{
		Type: symmetricPEMType,
		Headers: map[string]string{
			"Algorithm": string(alg),
		},
		Bytes: raw,
	}
	return pem.EncodeToMemory(block), nil
}
