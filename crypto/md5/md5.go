// Package md5 基于铜锁原生实现实现 MD5 哈希算法。
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
// MD5 输出 16 字节摘要，内部分组 64 字节；该算法已不抗碰撞（chosen-prefix 攻击
// 已实用化），不可用于数字签名或证书指纹，仅保留用于 HMAC-MD5、遗留指纹等
// 兼容场景。
//
// Package md5 provides the MD5 cryptographic hash algorithm backed by
// the Tongsuo native library. MD5 produces a 16-byte digest and operates
// on 64-byte internal blocks. It is collision-prone (chosen-prefix
// collisions are practical) and must not be used for digital signatures
// or certificate fingerprints; this package remains for compatibility
// (HMAC-MD5, legacy fingerprints).
package md5

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 MD5 摘要的字节长度。
	//
	// Size is the MD5 digest size in bytes (16 bytes / 128 bits).
	Size = 16
	// BlockSize 为 MD5 内部分组的字节长度。
	//
	// BlockSize is the MD5 internal block size in bytes (64 bytes / 512 bits).
	BlockSize = 64
)

// New 返回新的 MD5 哈希（hash.Hash）。
//
// New returns a new hash.Hash implementing MD5.
func New() hash.Hash { return digest.NewHash(core.MD5(), Size, BlockSize) }

// Sum 返回 data 的 MD5 摘要（16 字节 / 128 位），仅在底层铜锁 EVP 调用失败时 panic，正常输入长度下不会触发。
//
// Sum returns the 16-byte MD5 digest of data. It panics on an underlying
// Tongsuo EVP failure (not reachable for normal-sized inputs).
func Sum(data []byte) [Size]byte {
	sum, err := core.MD5().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
