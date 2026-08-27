// Package sha256 基于铜锁原生实现实现 SHA-256 哈希算法。
//
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
package sha256

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 SHA-256 摘要的字节长度。
	Size = 32
	// BlockSize 为 SHA-256 内部分组的字节长度。
	BlockSize = 64
)

// New 返回新的 SHA-256 哈希（hash.Hash）。
func New() hash.Hash { return digest.NewHash(core.SHA256(), Size, BlockSize) }

// Sum 返回 data 的 SHA-256 摘要。
func Sum(data []byte) [Size]byte {
	sum, err := core.SHA256().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
