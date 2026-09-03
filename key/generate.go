package key

import (
	"encoding/pem"
	"fmt"

	tongsrand "github.com/blue-cloud-net/tongsuo-go/crypto/rand"
)

// GenerateSymmetricKey 生成指定算法的随机对称密钥。
// alg 支持 AlgAES128、AlgAES256 与 AlgSM4；其它算法返回包装了
// ErrUnknownAlgorithm 的错误。密钥材料来自铜锁 CSPRNG（crypto/rand.Bytes）。
//
// GenerateSymmetricKey generates a fresh random symmetric key for the
// given algorithm.
// alg must be one of AlgAES128, AlgAES256 or AlgSM4; any other value
// returns an error wrapping ErrUnknownAlgorithm. The key material comes
// from the Tongsuo CSPRNG (crypto/rand.Bytes).
func GenerateSymmetricKey(alg Algorithm) (SymmetricKey, error) {
	var size int
	switch alg {
	case AlgAES128, AlgSM4:
		size = 16
	case AlgAES256:
		size = 32
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
	raw, err := tongsrand.Bytes(size)
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
// The Algorithm header restores AES-128 / AES-256 / SM4. A missing block,
// an unexpected block type, or an unknown algorithm yields the
// corresponding error (unknown algorithms wrap ErrUnknownAlgorithm).
func ParseSymmetricKey(p []byte) (SymmetricKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("key: no PEM block found")
	}
	if block.Type != symmetricPEMType {
		return nil, fmt.Errorf("key: unexpected PEM type %q", block.Type)
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
