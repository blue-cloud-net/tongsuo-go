// Package sm3 基于铜锁原生实现实现 GB/T 32905-2016 SM3 哈希算法。
// 提供标准库 hash.Hash 接口（New）与一次性便捷函数（Sum），返回 32 字节摘要。
//
// Package sm3 provides the GB/T 32905-2016 SM3 cryptographic hash algorithm
// backed by the Tongsuo native library. It exposes the standard hash.Hash
// interface via New and a one-shot helper Sum that returns a 32-byte digest.
package sm3

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	extdigest "github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

const (
	// Size 为 SM3 摘要的字节长度（32 字节 / 256 位）。
	//
	// Size is the byte length of an SM3 digest (256 bits).
	Size = 32
	// BlockSize 为 SM3 内部分组的字节长度。
	//
	// BlockSize is the internal block size in bytes of the SM3 compression function.
	BlockSize = 64
)

// New 返回新的 SM3 哈希（hash.Hash），支持流式写入与 Reset。
// 实际实现委托 internal/digest.NewHash（与 crypto/{md5,sha*} 共用同一实现）。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// New returns a new SM3 hash implementing the standard hash.Hash interface.
// It supports streaming writes and reuse via Reset. It panics only if the
// underlying Tongsuo initialization fails, which does not occur in normal use.
//
// The actual implementation delegates to internal/digest.NewHash, sharing
// the same digest.Hash type with crypto/{md5,sha1,sha256,sha512}.
func New() hash.Hash {
	return extdigest.NewHash(core.SM3(), Size, BlockSize)
}

// digest 复用 internal/digest.Hash；保留同名类型以维持文档与既有调用方
// 引用（crypto/sm3 的 example 与测试通过 *digest 构造 SM3 New）。
//
// digest reuses internal/digest.Hash; the local type alias preserves
// existing references in package docs and tests that construct *digest
// directly.
type digest = extdigest.Hash

// Sum 返回 data 的 SM3 摘要（GB/T 32905-2016）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// Sum returns the SM3 hash of data as a 32-byte array, per GB/T 32905-2016.
// It panics only if the underlying Tongsuo operation fails, which does not
// occur in normal use.
func Sum(data []byte) [Size]byte {
	sum, err := core.SM3().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [Size]byte
	copy(out[:], sum)
	return out
}
