// Package sha256 基于铜锁原生实现实现 SHA-256 哈希算法。
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
// SHA-256 输出 32 字节摘要，内部分组 64 字节；为 TLS、JWT 与大多数现代协议
// 推荐的默认哈希算法。
//
// Package sha256 provides the SHA-256 cryptographic hash algorithm
// backed by the Tongsuo native library. SHA-256 produces a 32-byte digest
// and operates on 64-byte internal blocks. It is the recommended default
// hash for TLS, JWT, and most modern protocols.
package sha256

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 SHA-256 摘要的字节长度。
	//
	// Size is the SHA-256 digest size in bytes (32 bytes / 256 bits).
	Size = 32
	// BlockSize 为 SHA-256 内部分组的字节长度。
	//
	// BlockSize is the SHA-256 internal block size in bytes (64 bytes / 512 bits).
	BlockSize = 64
)

// New 返回新的 SHA-256 哈希（hash.Hash）。
//
// New returns a new hash.Hash implementing SHA-256.
func New() hash.Hash { return digest.NewHash(core.SHA256(), Size, BlockSize) }

// Sum 返回 data 的 SHA-256 摘要（32 字节 / 256 位），仅在底层铜锁 EVP 调用失败时 panic，正常输入长度下不会触发。
//
// Sum returns the 32-byte SHA-256 digest of data. It panics on an
// underlying Tongsuo EVP failure (not reachable for normal-sized inputs).
func Sum(data []byte) [Size]byte {
	sum, err := core.SHA256().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
