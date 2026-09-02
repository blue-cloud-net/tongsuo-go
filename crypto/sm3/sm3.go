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
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// New returns a new SM3 hash implementing the standard hash.Hash interface.
// It supports streaming writes and reuse via Reset. It panics only if the
// underlying Tongsuo initialization fails, which does not occur in normal use.
func New() hash.Hash {
	ctx, err := core.NewDigestCtx(core.SM3())
	if err != nil {
		panic(err)
	}
	return &digest{ctx: ctx}
}

// digest 是 SM3 的 hash.Hash 实现。
//
// digest implements the standard hash.Hash interface for SM3.
type digest struct {
	ctx *core.DigestCtx
}

// Write 追加数据，实现 io.Writer 与 hash.Hash，返回写入字节数；底层铜锁 update 失败时返回错误。
//
// Write appends p to the digest state. It returns the number of bytes written
// and an error if the underlying Tongsuo update fails.
func (d *digest) Write(p []byte) (n int, err error) {
	if err := d.ctx.Update(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sum 返回当前数据的 SM3 摘要追加到 in 后，不改变内部状态。
//
// Sum appends the current SM3 digest to in and returns the resulting slice
// without altering the internal state.
func (d *digest) Sum(in []byte) []byte {
	sum, err := d.ctx.Sum()
	if err != nil {
		panic(err)
	}
	return append(in, sum...)
}

// Reset 重置哈希状态。
//
// Reset clears the digest state so the receiver can be reused.
func (d *digest) Reset() {
	if err := d.ctx.Reset(); err != nil {
		panic(err)
	}
}

// Size 返回摘要字节长度。
//
// Size returns the byte length of an SM3 digest.
func (d *digest) Size() int { return Size }

// BlockSize 返回内部分组字节长度。
//
// BlockSize returns the internal block size in bytes of the SM3 compression function.
func (d *digest) BlockSize() int { return BlockSize }

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
