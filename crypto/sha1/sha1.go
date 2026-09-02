// Package sha1 基于铜锁原生实现实现 SHA-1 哈希算法。
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum）。
// SHA-1 输出 20 字节摘要，内部分组 64 字节；该算法已不抗碰撞（SHAttered, 2017），
// 不可用于新的数字签名或证书指纹，仅保留用于兼容遗留 HMAC / TLS 1.0 / 1.1
// pin 存储等历史场景。
//
// Package sha1 provides the SHA-1 cryptographic hash algorithm backed by
// the Tongsuo native library. SHA-1 produces a 20-byte digest and
// operates on 64-byte internal blocks. It is collision-prone (SHAttered,
// 2017) and must not be used for new digital signatures or certificate
// fingerprints; this package remains for compatibility with legacy HMAC /
// TLS 1.0 / 1.1 pin stores.
package sha1

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 SHA-1 摘要的字节长度。
	//
	// Size is the SHA-1 digest size in bytes (20 bytes / 160 bits).
	Size = 20
	// BlockSize 为 SHA-1 内部分组的字节长度。
	//
	// BlockSize is the SHA-1 internal block size in bytes (64 bytes / 512 bits).
	BlockSize = 64
)

// New 返回新的 SHA-1 哈希（hash.Hash）。
//
// New returns a new hash.Hash implementing SHA-1.
func New() hash.Hash { return digest.NewHash(core.SHA1(), Size, BlockSize) }

// Sum 返回 data 的 SHA-1 摘要（20 字节 / 160 位），仅在底层铜锁 EVP 调用失败时 panic，正常输入长度下不会触发。
//
// Sum returns the 20-byte SHA-1 digest of data. It panics on an
// underlying Tongsuo EVP failure (not reachable for normal-sized inputs).
func Sum(data []byte) [Size]byte {
	sum, err := core.SHA1().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
