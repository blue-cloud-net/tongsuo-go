// Package sha512 基于铜锁原生实现实现 SHA-512 哈希算法。
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
// SHA-512 输出 64 字节摘要，内部分组 128 字节；更宽的分组在 64 位平台上
// 拥有比 SHA-256 更高的吞吐。
//
// Package sha512 provides the SHA-512 cryptographic hash algorithm
// backed by the Tongsuo native library. SHA-512 produces a 64-byte digest
// and operates on 128-byte internal blocks; the wider block size also
// gives it higher throughput than SHA-256 on 64-bit platforms.
package sha512

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 SHA-512 摘要的字节长度。
	//
	// Size is the SHA-512 digest size in bytes (64 bytes / 512 bits).
	Size = 64
	// BlockSize 为 SHA-512 内部分组的字节长度。
	//
	// BlockSize is the SHA-512 internal block size in bytes (128 bytes / 1024 bits).
	BlockSize = 128
)

// New 返回新的 SHA-512 哈希（hash.Hash）。
//
// New returns a new hash.Hash implementing SHA-512.
func New() hash.Hash { return digest.NewHash(core.SHA512(), Size, BlockSize) }

// Sum 返回 data 的 SHA-512 摘要（64 字节 / 512 位），仅在底层铜锁 EVP 调用失败时 panic，正常输入长度下不会触发。
//
// Sum returns the 64-byte SHA-512 digest of data. It panics on an
// underlying Tongsuo EVP failure (not reachable for normal-sized inputs).
func Sum(data []byte) [Size]byte {
	sum, err := core.SHA512().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
