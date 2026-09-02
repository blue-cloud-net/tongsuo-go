// Package hmac 基于铜锁原生实现实现 HMAC 消息认证码。
// 提供标准库 hash.Hash 接口（NewSM3 / NewSHA256 等）与一次性便捷函数（SumSM3 等）。
// HMAC 输出标签长度等于底层摘要长度（SM3=32、MD5=16、SHA-1=20、SHA-256=32、
// SHA-384=48、SHA-512=64）。基于 MD5 / SHA-1 的 HMAC 仅保留兼容用途，新协议
// 推荐使用 SHA-256 或更强者。
//
// Package hmac provides keyed-hash message authentication codes (HMAC,
// RFC 2104) backed by the Tongsuo native library. It exposes the
// standard library hash.Hash interface for SM3 / MD5 / SHA-1 / SHA-256
// / SHA-384 / SHA-512 and one-shot Sum-style helpers for the common
// configurations. The HMAC tag length equals the underlying digest
// length (SM3 = 32, MD5 = 16, SHA-1 = 20, SHA-256 = 32, SHA-384 = 48,
// SHA-512 = 64). MD5 and SHA-1 based HMAC are exported for compatibility
// only — use SHA-256 or stronger for new protocols.
package hmac

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// NewSM3 返回 HMAC-SM3 的 hash.Hash。
//
// 输出标签 32 字节（SM3 摘要长度）。key 为 HMAC 密钥，长度任意。
//
// NewSM3 returns a hash.Hash implementing HMAC-SM3.
//
// The output tag is 32 bytes (SM3 digest size). key is the HMAC key and
// may be any length.
func NewSM3(key []byte) hash.Hash { return newHMAC(key, core.SM3()) }

// NewMD5 返回 HMAC-MD5 的 hash.Hash。
//
// 输出标签 16 字节（MD5 摘要长度）。MD5 已不抗碰撞，本函数仅用于兼容遗留系统，
// 新协议推荐 NewSHA256 或 NewSM3。
//
// NewMD5 returns a hash.Hash implementing HMAC-MD5.
//
// The output tag is 16 bytes (MD5 digest size). MD5 is collision-prone;
// this helper exists for compatibility with legacy systems — prefer
// NewSHA256 or NewSM3 for new protocols.
func NewMD5(key []byte) hash.Hash { return newHMAC(key, core.MD5()) }

// NewSHA1 返回 HMAC-SHA1 的 hash.Hash。
//
// 输出标签 20 字节（SHA-1 摘要长度）。SHA-1 用于数字签名已不抗碰撞，但作为 MAC
// 仍可在兼容场景使用；新协议推荐 NewSHA256 或 NewSM3。
//
// NewSHA1 returns a hash.Hash implementing HMAC-SHA1.
//
// The output tag is 20 bytes (SHA-1 digest size). SHA-1 is collision-prone
// for digital signatures; HMAC-SHA1 remains acceptable as a MAC for
// compatibility, but prefer NewSHA256 or NewSM3 for new protocols.
func NewSHA1(key []byte) hash.Hash { return newHMAC(key, core.SHA1()) }

// NewSHA256 返回 HMAC-SHA256 的 hash.Hash。
//
// 输出标签 32 字节（SHA-256 摘要长度）。为新协议推荐的默认选项。
//
// NewSHA256 returns a hash.Hash implementing HMAC-SHA256.
//
// The output tag is 32 bytes (SHA-256 digest size). This is the
// recommended default for new protocols.
func NewSHA256(key []byte) hash.Hash { return newHMAC(key, core.SHA256()) }

// NewSHA384 返回 HMAC-SHA384 的 hash.Hash。
//
// 输出标签 48 字节（SHA-384 摘要长度）。
//
// NewSHA384 returns a hash.Hash implementing HMAC-SHA384.
//
// The output tag is 48 bytes (SHA-384 digest size).
func NewSHA384(key []byte) hash.Hash { return newHMAC(key, core.SHA384()) }

// NewSHA512 返回 HMAC-SHA512 的 hash.Hash。
//
// 输出标签 64 字节（SHA-512 摘要长度）。在性能敏感场景下 64 字节标签可按需截断。
//
// NewSHA512 returns a hash.Hash implementing HMAC-SHA512.
//
// The output tag is 64 bytes (SHA-512 digest size); for performance-
// sensitive use cases 64-byte tags can be truncated.
func NewSHA512(key []byte) hash.Hash { return newHMAC(key, core.SHA512()) }

// SumSM3 一次性计算 HMAC-SM3，返回 32 字节 HMAC-SM3 标签（实现方式：分配一个新的 NewSM3 实例，写入 data，复制其标签）。
//
// SumSM3 returns the 32-byte HMAC-SM3 of data under key, computed by
// allocating a fresh HMAC via NewSM3, writing data, and copying the
// tag.
func SumSM3(key, data []byte) []byte {
	h := NewSM3(key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// SumSHA256 一次性计算 HMAC-SHA256，返回 32 字节 HMAC-SHA256 标签（实现方式：分配一个新的 NewSHA256 实例，写入 data，复制其标签）。
//
// SumSHA256 returns the 32-byte HMAC-SHA256 of data under key, computed
// by allocating a fresh HMAC via NewSHA256, writing data, and copying
// the tag.
func SumSHA256(key, data []byte) []byte {
	h := NewSHA256(key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// SumSHA384 一次性计算 HMAC-SHA384，返回 48 字节 HMAC-SHA384 标签（实现方式：分配一个新的 NewSHA384 实例，写入 data，复制其标签）。
//
// SumSHA384 returns the 48-byte HMAC-SHA384 of data under key, computed
// by allocating a fresh HMAC via NewSHA384, writing data, and copying
// the tag.
func SumSHA384(key, data []byte) []byte {
	h := NewSHA384(key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// hmac 是 HMAC 的 hash.Hash 实现。
//
// hmac implements the standard hash.Hash interface for HMAC.
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
//
// Write appends p to the HMAC state, satisfying both io.Writer and
// hash.Hash. It returns the number of bytes written.
func (h *hmac) Write(p []byte) (n int, err error) {
	if err := h.ctx.Update(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sum 返回当前数据的 HMAC 结果追加到 in 后，不改变内部状态。
//
// Sum appends the current HMAC tag to in and returns the resulting slice
// without altering the internal state.
func (h *hmac) Sum(in []byte) []byte {
	sum, err := h.ctx.Sum()
	if err != nil {
		panic(err)
	}
	return append(in, sum...)
}

// Reset 重置 HMAC 状态（保留密钥与摘要算法）。
//
// Reset clears the HMAC state so the receiver can be reused. The key
// and digest algorithm are retained.
func (h *hmac) Reset() {
	if err := h.ctx.Reset(); err != nil {
		panic(err)
	}
}

// Size 返回摘要字节长度。
//
// Size returns the HMAC tag size in bytes.
func (h *hmac) Size() int { return h.size }

// BlockSize 返回内部分组字节长度。
//
// BlockSize returns the HMAC's internal block size in bytes.
func (h *hmac) BlockSize() int { return h.block }
