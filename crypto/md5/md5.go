// Package md5 基于铜锁原生实现实现 MD5 哈希算法。
//
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
package md5

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 MD5 摘要的字节长度。
	Size = 16
	// BlockSize 为 MD5 内部分组的字节长度。
	BlockSize = 64
)

// New 返回新的 MD5 哈希（hash.Hash）。
func New() hash.Hash { return digest.NewHash(core.MD5(), Size, BlockSize) }

// Sum 返回 data 的 MD5 摘要。
func Sum(data []byte) [Size]byte {
	sum, err := core.MD5().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
