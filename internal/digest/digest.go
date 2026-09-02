// Package digest 提供基于核心层摘要上下文的可复用 hash.Hash 实现。
// 供 crypto/md5、crypto/sha1、crypto/sha256、crypto/sha512 等子包共用。
//
// Package digest provides reusable hash.Hash implementations backed by
// core-layer digest contexts. It is consumed by the crypto/md5,
// crypto/sha1, crypto/sha256, crypto/sha512 and similar subpackages.
package digest

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// NewHash 返回实现 hash.Hash 的摘要对象（基于铜锁 EVP_MD_CTX）。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewHash returns a hash.Hash implementation backed by a Tongsuo
// EVP_MD_CTX. It panics only when the underlying Tongsuo initialization
// fails, which does not occur in normal use.
func NewHash(d *core.Digest, size, block int) hash.Hash {
	ctx, err := core.NewDigestCtx(d)
	if err != nil {
		panic(err)
	}
	return &Hash{ctx: ctx, size: size, block: block}
}

// Hash 是基于铜锁摘要上下文的标准 hash.Hash 实现。
//
// Hash is a standard hash.Hash implementation backed by a Tongsuo
// digest context.
type Hash struct {
	ctx   *core.DigestCtx
	size  int
	block int
}

// Write 追加数据，实现 io.Writer 与 hash.Hash。
//
// Write appends data and satisfies both io.Writer and hash.Hash.
func (h *Hash) Write(p []byte) (n int, err error) {
	if err := h.ctx.Update(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sum 返回当前数据的摘要追加到 in 后，不改变内部状态。
//
// Sum returns the current digest appended to in without mutating
// the internal state.
func (h *Hash) Sum(in []byte) []byte {
	sum, err := h.ctx.Sum()
	if err != nil {
		panic(err)
	}
	return append(in, sum...)
}

// Reset 重置哈希状态。
//
// Reset clears the hash state.
func (h *Hash) Reset() {
	if err := h.ctx.Reset(); err != nil {
		panic(err)
	}
}

// Size 返回摘要字节长度。
//
// Size returns the digest length in bytes.
func (h *Hash) Size() int { return h.size }

// BlockSize 返回内部分组字节长度。
//
// BlockSize returns the internal block length in bytes.
func (h *Hash) BlockSize() int { return h.block }
