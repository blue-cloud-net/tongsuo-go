package core

import (
	"fmt"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Digest 表示一个摘要算法描述符（EVP_MD 的包装）。
// EVP_MD 是铜锁内置的常量算法描述符，不拥有所有权，无需释放。
type Digest struct {
	handle *Handle
	size   int
	block  int
}

// newDigest 包装算法描述符指针。
func newDigest(md unsafe.Pointer) *Digest {
	if md == nil {
		return nil
	}
	return &Digest{
		handle: NewHandle(md, false, nil),
		size:   native.EVP_MD_get_size(md),
		block:  native.EVP_MD_get_block_size(md),
	}
}

// SM3 返回 SM3 摘要算法（GB/T 32905-2016）。
func SM3() *Digest { return newDigest(native.EVP_sm3()) }

// MD5 返回 MD5 摘要算法。
func MD5() *Digest { return newDigest(native.EVP_md5()) }

// SHA1 返回 SHA-1 摘要算法。
func SHA1() *Digest { return newDigest(native.EVP_sha1()) }

// SHA224 返回 SHA-224 摘要算法。
func SHA224() *Digest { return newDigest(native.EVP_sha224()) }

// SHA256 返回 SHA-256 摘要算法。
func SHA256() *Digest { return newDigest(native.EVP_sha256()) }

// SHA384 返回 SHA-384 摘要算法。
func SHA384() *Digest { return newDigest(native.EVP_sha384()) }

// SHA512 返回 SHA-512 摘要算法。
func SHA512() *Digest { return newDigest(native.EVP_sha512()) }

// Size 返回摘要长度（字节）。
func (d *Digest) Size() int { return d.size }

// BlockSize 返回内部分组长度（字节）。
func (d *Digest) BlockSize() int { return d.block }

// OneShot 一次性计算 data 的摘要。
func (d *Digest) OneShot(data []byte) ([]byte, error) {
	if d == nil || d.handle == nil || d.handle.IsClosed() {
		return nil, fmt.Errorf("digest: invalid digest")
	}
	out := make([]byte, d.size)
	var n int
	if !native.X_EVP_Digest(d.handle.Ptr(), data, out, &n) {
		return nil, NewOpError("digest: EVP_Digest", native.PopError())
	}
	return out[:n], nil
}

// DigestCtx 表示一个摘要计算上下文（EVP_MD_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
type DigestCtx struct {
	handle *Handle
	digest *Digest
}

// NewDigestCtx 创建并初始化摘要上下文。
func NewDigestCtx(d *Digest) (*DigestCtx, error) {
	if d == nil || d.handle == nil || d.handle.IsClosed() {
		return nil, fmt.Errorf("digest: invalid digest")
	}
	ctx := native.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, NewOpError("digest: EVP_MD_CTX_new", native.PopError())
	}
	h := NewHandle(ctx, true, native.EVP_MD_CTX_free)
	if !native.EVP_DigestInit_ex(ctx, d.handle.Ptr(), nil) {
		_ = h.Close()
		return nil, NewOpError("digest: EVP_DigestInit_ex", native.PopError())
	}
	return &DigestCtx{handle: h, digest: d}, nil
}

// Update 追加数据到摘要上下文。
func (c *DigestCtx) Update(data []byte) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("digest: context closed")
	}
	if !native.EVP_DigestUpdate(c.handle.Ptr(), data) {
		return NewOpError("digest: EVP_DigestUpdate", native.PopError())
	}
	return nil
}

// Sum 返回当前已写入数据的摘要，且不改变上下文状态（通过复制上下文实现）。
func (c *DigestCtx) Sum() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("digest: context closed")
	}
	copyCtx := native.EVP_MD_CTX_new()
	if copyCtx == nil {
		return nil, NewOpError("digest: EVP_MD_CTX_new", native.PopError())
	}
	defer native.EVP_MD_CTX_free(copyCtx)
	if !native.EVP_MD_CTX_copy_ex(copyCtx, c.handle.Ptr()) {
		return nil, NewOpError("digest: EVP_MD_CTX_copy_ex", native.PopError())
	}
	out := make([]byte, c.digest.Size())
	var n int
	if !native.EVP_DigestFinal_ex(copyCtx, out, &n) {
		return nil, NewOpError("digest: EVP_DigestFinal_ex", native.PopError())
	}
	return out[:n], nil
}

// Final 完成计算并返回摘要。调用后上下文需 Reset 或 Close 才能复用。
func (c *DigestCtx) Final() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("digest: context closed")
	}
	out := make([]byte, c.digest.Size())
	var n int
	if !native.EVP_DigestFinal_ex(c.handle.Ptr(), out, &n) {
		return nil, NewOpError("digest: EVP_DigestFinal_ex", native.PopError())
	}
	return out[:n], nil
}

// Reset 重置上下文，可复用。
func (c *DigestCtx) Reset() error {
	if c.handle.IsClosed() {
		return fmt.Errorf("digest: context closed")
	}
	if !native.EVP_DigestInit_ex(c.handle.Ptr(), c.digest.handle.Ptr(), nil) {
		return NewOpError("digest: EVP_DigestInit_ex(reset)", native.PopError())
	}
	return nil
}

// Close 释放底层句柄。幂等。
func (c *DigestCtx) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}
