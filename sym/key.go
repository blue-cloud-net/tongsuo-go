package sym

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/rand"
)

// Algorithm 标识对称算法。
//
// Algorithm names a symmetric cipher algorithm.
type Algorithm string

// 对称算法常量（与 CLI 命名前缀对齐）。
//
// Symmetric algorithm constants (aligned with the CLI naming prefixes).
const (
	// AlgAES128 标识 AES-128（128 位 / 16 字节密钥）。
	//
	// AlgAES128 identifies AES-128 (128-bit / 16-byte key).
	AlgAES128 Algorithm = "AES-128"
	// AlgAES256 标识 AES-256（256 位 / 32 字节密钥）。
	//
	// AlgAES256 identifies AES-256 (256-bit / 32-byte key).
	AlgAES256 Algorithm = "AES-256"
	// AlgSM4 标识 SM4（GB/T 32907，128 位 / 16 字节密钥）。
	//
	// AlgSM4 identifies SM4 (GB/T 32907, 128-bit / 16-byte key).
	AlgSM4 Algorithm = "SM4"
)

// ErrUnknownAlgorithm 表示按名分发时传入的算法不在受支持集合内。
// 用 errors.Is(err, ErrUnknownAlgorithm) 判定。
//
// ErrUnknownAlgorithm reports that a given algorithm is not in the
// supported set. Test with errors.Is(err, ErrUnknownAlgorithm).
var ErrUnknownAlgorithm = errors.New("sym: unknown algorithm")

// symmetricPEMType 是对称密钥 PEM 块类型。
//
// symmetricPEMType is the PEM block type used for symmetric keys.
const symmetricPEMType = "SYMMETRIC KEY"

// Key 是所有对称密钥与非对称密钥对象的统一接口（参数命名空间）：
// 仅暴露 Algorithm() 用于分组，不持有原生句柄。
//
// 对称密钥还应实现 SymmetricKey（含 Bytes/Size/Equal/Marshal）。
//
// Key is the top-level interface shared by all symmetric and asymmetric
// key objects: it exposes Algorithm() for grouping and holds no native
// handle. Symmetric keys additionally implement SymmetricKey.
type Key interface {
	Algorithm() Algorithm
}

// SymmetricKey 表示对称密钥对象（AES / SM4）。
//
// 对称密钥以原始字节为密钥材料。具体包装类型 AESKey 与 SM4Key 实现本接口：
// Bytes 返回原始密钥字节的拷贝；Size 返回字节长度；Marshal 以自定义 PEM 块
// （Type = "SYMMETRIC KEY"）导出。对称密钥不持有原生句柄，无需 Close。
//
// SymmetricKey represents a symmetric key.
//
// Symmetric keys (AES, SM4) use raw bytes as key material. The concrete
// wrapper types AESKey and SM4Key implement this interface: Bytes
// returns a copy of the raw key bytes, Size reports the length in bytes,
// and Marshal exports the key as a custom PEM block (Type = "SYMMETRIC
// KEY"). Symmetric keys own no native handle and need no Close.
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

// AESKey 表示 AES 对称密钥（AES-128 或 AES-256）。
//
// 通过 NewAESKey 构造并校验长度（16 或 32 字节），亦可由 GenerateSymmetricKey
// 生成随机密钥。底层不持有原生句柄，无需 Close。
//
// AESKey represents an AES symmetric key (AES-128 or AES-256).
//
// Construct one via NewAESKey, which validates the length (16 or 32
// bytes), or obtain a fresh random key from GenerateSymmetricKey. It
// owns no native handle and needs no Close.
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
	case AES128KeySize:
		alg = AlgAES128
	case AES256KeySize:
		alg = AlgAES256
	default:
		return nil, fmt.Errorf("sym: invalid AES key size %d, want %d or %d", len(raw), AES128KeySize, AES256KeySize)
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
// 块头携带 Algorithm 以标识 AES-128 / AES-256；编码过程不失败。
//
// Marshal serializes the key as a PEM block (Type = "SYMMETRIC KEY").
// The Algorithm header records AES-128 / AES-256; encoding cannot fail.
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
	if len(raw) != SM4KeySize {
		return nil, fmt.Errorf("sym: invalid SM4 key size %d, want %d", len(raw), SM4KeySize)
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
//
// Bytes returns a copy of the raw key bytes.
func (k *SM4Key) Bytes() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.raw...)
}

// Equal 报告 k 与 other 是否表示同一 SM4 密钥。
//
// Equal reports whether k and other denote the same SM4 key.
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
//
// Marshal serializes the key as a PEM block (Type = "SYMMETRIC KEY").
func (k *SM4Key) Marshal() ([]byte, error) {
	return marshalSymmetric(AlgSM4, k.raw)
}

// GenerateSymmetricKey 生成指定算法的随机对称密钥。
// alg 支持 AlgAES128、AlgAES256 与 AlgSM4；其它算法返回包装了
// ErrUnknownAlgorithm 的错误。密钥材料来自铜锁 CSPRNG（rand.Bytes）。
//
// GenerateSymmetricKey generates a fresh random symmetric key for the
// given algorithm.
// alg must be one of AlgAES128, AlgAES256 or AlgSM4; any other value
// returns an error wrapping ErrUnknownAlgorithm. The key material
// comes from the Tongsuo CSPRNG (rand.Bytes).
func GenerateSymmetricKey(alg Algorithm) (SymmetricKey, error) {
	var size int
	switch alg {
	case AlgAES128, AlgSM4:
		size = SM4KeySize
	case AlgAES256:
		size = AES256KeySize
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
	raw, err := rand.Bytes(size)
	if err != nil {
		return nil, err
	}
	switch alg {
	case AlgAES128, AlgAES256:
		return NewAESKey(raw)
	default:
		return NewSM4Key(raw)
	}
}

// ParseSymmetricKey 从 PEM 块（Type = "SYMMETRIC KEY"）解析对称密钥。
// 依据块头 Algorithm 还原 AES-128 / AES-256 / SM4；块缺失、类型不符或算法
// 未知时分别返回相应错误（未知算法包装 ErrUnknownAlgorithm）。
//
// ParseSymmetricKey parses a symmetric key from a PEM block
// (Type = "SYMMETRIC KEY").
// The Algorithm header restores AES-128 / AES-256 / SM4. A missing
// block, an unexpected block type, or an unknown algorithm yields the
// corresponding error (unknown algorithms wrap ErrUnknownAlgorithm).
func ParseSymmetricKey(p []byte) (SymmetricKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("sym: no PEM block found")
	}
	if block.Type != symmetricPEMType {
		return nil, fmt.Errorf("sym: unexpected PEM type %q", block.Type)
	}
	alg := Algorithm(block.Headers["Algorithm"])
	switch alg {
	case AlgAES128, AlgAES256:
		return NewAESKey(block.Bytes)
	case AlgSM4:
		return NewSM4Key(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
}

// marshalSymmetric 把 (alg, raw) 编码为携带 Algorithm 头的 PEM 块。
// 编码不可能失败。
//
// marshalSymmetric encodes a (alg, raw) pair as a PEM block carrying an
// Algorithm header. Encoding cannot fail.
func marshalSymmetric(alg Algorithm, raw []byte) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type: symmetricPEMType,
		Headers: map[string]string{
			"Algorithm": string(alg),
		},
		Bytes: raw,
	}), nil
}
