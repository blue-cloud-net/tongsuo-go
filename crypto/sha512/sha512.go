// Package sha512 基于铜锁原生实现实现 SHA-512 哈希算法。
//
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
package sha512

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 SHA-512 摘要的字节长度。
	Size = 64
	// BlockSize 为 SHA-512 内部分组的字节长度。
	BlockSize = 128
)

// New 返回新的 SHA-512 哈希（hash.Hash）。
func New() hash.Hash { return digest.NewHash(core.SHA512(), Size, BlockSize) }

// Sum 返回 data 的 SHA-512 摘要。
func Sum(data []byte) [Size]byte {
	sum, err := core.SHA512().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
