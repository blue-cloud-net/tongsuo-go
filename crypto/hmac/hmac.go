// Package hmac 基于铜锁原生实现实现 HMAC 消息认证码。
//
// 提供标准库 hash.Hash 接口（NewSM3 / NewSHA256 等）与一次性便捷函数（SumSM3 等）。
package hmac

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// NewSM3 返回 HMAC-SM3 的 hash.Hash。
func NewSM3(key []byte) hash.Hash { return newHMAC(key, core.SM3()) }

// NewMD5 返回 HMAC-MD5 的 hash.Hash。
func NewMD5(key []byte) hash.Hash { return newHMAC(key, core.MD5()) }

// NewSHA1 返回 HMAC-SHA1 的 hash.Hash。
func NewSHA1(key []byte) hash.Hash { return newHMAC(key, core.SHA1()) }

// NewSHA256 返回 HMAC-SHA256 的 hash.Hash。
func NewSHA256(key []byte) hash.Hash { return newHMAC(key, core.SHA256()) }

// NewSHA512 返回 HMAC-SHA512 的 hash.Hash。
func NewSHA512(key []byte) hash.Hash { return newHMAC(key, core.SHA512()) }

// SumSM3 一次性计算 HMAC-SM3。
func SumSM3(key, data []byte) []byte {
	h := NewSM3(key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// SumSHA256 一次性计算 HMAC-SHA256。
func SumSHA256(key, data []byte) []byte {
	h := NewSHA256(key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// hmac 是 HMAC 的 hash.Hash 实现。
type hmac struct {
	ctx   *core.HmacCtx
	size  int
	block int
}

func newHMAC(key []byte, d *core.Digest) hash.Hash {
	ctx, err := core.NewHmacCtx(d, key)
	if err != nil {
		panic(err)
	}
	return &hmac{ctx: ctx, size: d.Size(), block: d.BlockSize()}
}

// Write 追加数据，实现 io.Writer 与 hash.Hash。
func (h *hmac) Write(p []byte) (n int, err error) {
	if err := h.ctx.Update(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sum 返回当前数据的 HMAC 结果追加到 in 后，不改变内部状态。
func (h *hmac) Sum(in []byte) []byte {
	sum, err := h.ctx.Sum()
	if err != nil {
		panic(err)
	}
	return append(in, sum...)
}

// Reset 重置 HMAC 状态（保留密钥与摘要算法）。
func (h *hmac) Reset() {
	if err := h.ctx.Reset(); err != nil {
		panic(err)
	}
}

// Size 返回摘要字节长度。
func (h *hmac) Size() int { return h.size }

// BlockSize 返回内部分组字节长度。
func (h *hmac) BlockSize() int { return h.block }
