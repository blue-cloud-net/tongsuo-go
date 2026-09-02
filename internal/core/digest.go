package core

import (
	"fmt"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Digest 表示一个摘要算法描述符（EVP_MD 的包装）。
// EVP_MD 是铜锁内置的常量算法描述符，不拥有所有权，无需释放。
//
// Digest is the Go wrapper around an OpenSSL EVP_MD message-digest
// descriptor. The wrapped EVP_MD is a Tongsuo-owned constant object; the
// Digest does NOT own the underlying pointer (Handle.owned == false) and
// the caller is not required to release it.
type Digest struct {
	handle *Handle
	size   int
	block  int
}

// newDigest 包装算法描述符指针。
//
// newDigest wraps a raw message-digest descriptor pointer into a
// *Digest, returning nil when md is nil.
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
//
// SM3 returns the SM3 hash descriptor (GB/T 32905-2016), 32-byte output.
func SM3() *Digest { return newDigest(native.EVP_sm3()) }

// MD5 返回 MD5 摘要算法（16 字节输出）。
// MD5 在密码学上已被攻破，请勿用于安全用途。
//
// MD5 returns the MD5 hash descriptor, 16-byte output. MD5 is
// cryptographically broken and SHOULD NOT be used for security purposes.
func MD5() *Digest { return newDigest(native.EVP_md5()) }

// SHA1 返回 SHA-1 摘要算法（20 字节输出）。
// SHA-1 在抗碰撞性方面已废弃；推荐使用 SHA-256 或更强算法。
//
// SHA1 returns the SHA-1 hash descriptor, 20-byte output. SHA-1 is
// deprecated for collision resistance; use SHA-256 or stronger.
func SHA1() *Digest { return newDigest(native.EVP_sha1()) }

// SHA224 返回 SHA-224 摘要算法（28 字节输出，SHA-256 截断到 224 位）。
//
// SHA224 returns the SHA-224 hash descriptor (SHA-256 truncated to
// 224 bits), 28-byte output.
func SHA224() *Digest { return newDigest(native.EVP_sha224()) }

// SHA256 返回 SHA-256 摘要算法。
//
// SHA256 returns the SHA-256 hash descriptor, 32-byte output.
func SHA256() *Digest { return newDigest(native.EVP_sha256()) }

// SHA384 返回 SHA-384 摘要算法（48 字节输出，SHA-512 截断到 384 位）。
//
// SHA384 returns the SHA-384 hash descriptor (SHA-512 truncated to
// 384 bits), 48-byte output.
func SHA384() *Digest { return newDigest(native.EVP_sha384()) }

// SHA512 返回 SHA-512 摘要算法。
//
// SHA512 returns the SHA-512 hash descriptor, 64-byte output.
func SHA512() *Digest { return newDigest(native.EVP_sha512()) }

// Size 返回摘要长度（字节），例如 SHA-256 为 32、SHA-512 为 64、MD5 为 16。
//
// Size returns the digest output length in bytes (for example 32 for
// SHA-256, 64 for SHA-512, 16 for MD5).
func (d *Digest) Size() int { return d.size }

// BlockSize 返回内部分组长度（字节），例如 SHA-256 为 64、SHA-512 为 128、SM3 为 64。
//
// BlockSize returns the internal block size of the digest in bytes
// (for example 64 for SHA-256, 128 for SHA-512, 64 for SM3).
func (d *Digest) BlockSize() int { return d.block }

// OneShot 一次性计算 data 的摘要。
// 等价于分配一个临时 DigestCtx，依次调用 Update 与 Final，返回字节长度为 Digest.Size()。
// nil 接收者或已释放的句柄返回错误 "digest: invalid digest"；底层 OpenSSL 失败包装为 OpError。
//
// OneShot computes the digest of data in a single call and returns the
// resulting bytes (length Digest.Size()). It is equivalent to allocating
// a temporary DigestCtx, calling Update and Final. The method returns
// the error "digest: invalid digest" on a nil receiver or an
// already-released handle; underlying OpenSSL failures are wrapped as
// OpError.
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
// 类型支持流式摘要接口（Update + Final）以及通过 Sum 进行非破坏性探测；通过内部 Handle 拥有底层 EVP_MD_CTX。
//
// DigestCtx is the Go wrapper around an OpenSSL EVP_MD_CTX and supports
// the streaming digest interface (Update + Final) as well as
// non-destructive probing via Sum. The type owns the underlying
// EVP_MD_CTX through an internal Handle and the caller MUST invoke
// Close to release the context once they are done with it.
type DigestCtx struct {
	handle *Handle
	digest *Digest
}

// NewDigestCtx 创建并初始化摘要上下文。
// 返回的 *DigestCtx 拥有底层 EVP_MD_CTX；调用方负责调用 Close 释放。
// d 为 nil 或已关闭时返回错误 "digest: invalid digest"；绑定层失败包装为 OpError。
//
// NewDigestCtx creates and initialises a digest context bound to the
// supplied Digest descriptor. The returned *DigestCtx owns the underlying
// EVP_MD_CTX and the caller is responsible for invoking Close. A nil d
// or an already-closed d yields the error "digest: invalid digest";
// failures from the binding layer are wrapped as OpError.
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

// Update 追加数据到摘要上下文。可在 Final 之前重复调用。
// 上下文已释放时返回错误 "digest: context closed"；底层 OpenSSL 失败包装为 OpError。
//
// Update appends data to the in-progress digest computation. It may be
// called repeatedly before Final. The method returns the error
// "digest: context closed" when the context has been released and
// wraps any underlying OpenSSL failure as OpError.
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
// 内部复制底层 EVP_MD_CTX，因此 Final 仍可后续调用；结果长度为 Digest.Size()。
//
// Sum returns the digest of all data written so far without mutating the
// receiver's state. The receiver's underlying EVP_MD_CTX is duplicated
// internally so that Final may still be invoked afterwards. The result
// has length Digest.Size().
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
// 返回字节长度为 Digest.Size()。Final 之后必须 Reset（以相同摘要复用）或 Close 才能再次 Update；否则后续操作未定义。
//
// Final finalises the digest computation and returns the resulting bytes
// length Digest.Size(). After Final the context MUST be Reset (to reuse
// with the same digest) or Close before any further Update call;
// otherwise subsequent operations are undefined.
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
// 保留原摘要算法绑定，仅清空累积输入，可用于新一轮摘要计算。
//
// Reset clears accumulated input while keeping the same digest
// algorithm bound to the context, so the receiver may be reused for a
// new digest computation.
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
// nil 接收者返回 nil；Close 之后所有其他方法返回 "digest: context closed"。
//
// Close releases the underlying EVP_MD_CTX. The call is idempotent and
// returns nil on a nil receiver; after Close all other methods on the
// receiver return "digest: context closed".
func (c *DigestCtx) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}
