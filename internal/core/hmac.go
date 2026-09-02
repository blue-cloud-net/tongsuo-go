package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// HmacCtx 表示一个 HMAC 计算上下文（HMAC_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
// 类型支持流式 HMAC 接口（Update + Final）以及通过 Sum 进行非破坏性探测；通过内部 Handle 拥有底层 HMAC_CTX。
//
// HmacCtx is the Go wrapper around an OpenSSL HMAC_CTX and supports the
// streaming HMAC interface (Update + Final) as well as non-destructive
// probing via Sum. The type owns the underlying HMAC_CTX through an
// internal Handle and the caller must invoke Close to release the
// context once they are done with it.
type HmacCtx struct {
	handle *Handle
	digest *Digest
}

// NewHmacCtx 创建并初始化 HMAC 上下文（设置密钥与摘要算法）。
// key 可为任意长度，长度超过摘要块大小时构造器会先对其进行哈希（标准 HMAC 语义）。
// 返回的 *HmacCtx 拥有底层 HMAC_CTX；调用方必须调用 Close 释放。
// d 为 nil 或已关闭时返回错误 "hmac: invalid digest"；绑定层失败包装为 OpError。
//
// NewHmacCtx creates and initializes an HMAC context by binding it to the
// digest algorithm d and the supplied key. The key may be any length; for
// keys longer than the digest block size the constructor hashes them
// first (standard HMAC semantics). The returned *HmacCtx owns the
// underlying HMAC_CTX and the caller must invoke Close to release it.
// A nil d or an already-closed d yields the error "hmac: invalid digest";
// failures from the binding layer are wrapped as OpError.
func NewHmacCtx(d *Digest, key []byte) (*HmacCtx, error) {
	if d == nil || d.handle == nil || d.handle.IsClosed() {
		return nil, fmt.Errorf("hmac: invalid digest")
	}
	ctx := native.HMAC_CTX_new()
	if ctx == nil {
		return nil, NewOpError("hmac: HMAC_CTX_new", native.PopError())
	}
	h := NewHandle(ctx, true, native.HMAC_CTX_free)
	if !native.HMAC_Init_ex(ctx, key, d.handle.Ptr()) {
		_ = h.Close()
		return nil, NewOpError("hmac: HMAC_Init_ex", native.PopError())
	}
	return &HmacCtx{handle: h, digest: d}, nil
}

// Update 追加数据到 HMAC 上下文。
// 可在 Final 之前重复调用。上下文已释放时返回错误 "hmac: context closed"；
// 底层 OpenSSL 失败包装为 OpError。
//
// Update appends data to the in-progress HMAC computation. It may be
// called repeatedly before Final. The method returns the error
// "hmac: context closed" when the context has been released and wraps
// any underlying OpenSSL failure as OpError.
func (c *HmacCtx) Update(data []byte) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("hmac: context closed")
	}
	if !native.HMAC_Update(c.handle.Ptr(), data) {
		return NewOpError("hmac: HMAC_Update", native.PopError())
	}
	return nil
}

// Final 完成计算并返回 HMAC 结果。调用后需 Reset 或 Close 才能复用。
// 返回的 MAC 长度为 Digest.Size()。Final 之后必须调用 Reset（以相同密钥与摘要复用）
// 或 Close 才能再次 Update；否则后续操作未定义。
//
// Final finalises the HMAC computation and returns the resulting MAC of
// length Digest.Size(). After Final the context MUST be Reset (to reuse
// with the same key and digest) or Close before any further Update call;
// otherwise subsequent operations are undefined.
func (c *HmacCtx) Final() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("hmac: context closed")
	}
	out := make([]byte, c.digest.Size())
	var n int
	if !native.HMAC_Final(c.handle.Ptr(), out, &n) {
		return nil, NewOpError("hmac: HMAC_Final", native.PopError())
	}
	return out[:n], nil
}

// Sum 返回当前已写入数据的 HMAC 结果，不改变上下文状态（通过复制上下文实现）。
// 内部复制底层 HMAC_CTX，因此 Final 仍可后续调用。返回切片长度为 Digest.Size()。
//
// Sum returns the HMAC value of all data written so far without mutating
// the receiver's state. The receiver's underlying HMAC_CTX is duplicated
// internally so that Final may still be invoked afterwards. The slice
// has length Digest.Size().
func (c *HmacCtx) Sum() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("hmac: context closed")
	}
	copyCtx := native.HMAC_CTX_new()
	if copyCtx == nil {
		return nil, NewOpError("hmac: HMAC_CTX_new", native.PopError())
	}
	defer native.HMAC_CTX_free(copyCtx)
	if !native.HMAC_CTX_copy(copyCtx, c.handle.Ptr()) {
		return nil, NewOpError("hmac: HMAC_CTX_copy", native.PopError())
	}
	out := make([]byte, c.digest.Size())
	var n int
	if !native.HMAC_Final(copyCtx, out, &n) {
		return nil, NewOpError("hmac: HMAC_Final", native.PopError())
	}
	return out[:n], nil
}

// Reset 重置上下文，可复用（保留原密钥与摘要算法）。
// 按 OpenSSL 语义，向 HMAC_Init_ex 传入 nil 作为密钥会保留原密钥。
//
// Reset clears accumulated input while keeping the original key and
// digest algorithm bound to the context, so the receiver may be reused
// for a new HMAC computation. Passing nil as the key to HMAC_Init_ex
// preserves the previous key per OpenSSL semantics.
func (c *HmacCtx) Reset() error {
	if c.handle.IsClosed() {
		return fmt.Errorf("hmac: context closed")
	}
	// 用空密钥重新 Init_ex 会保留原密钥（OpenSSL 语义：key 为 NULL 时沿用）。
	if !native.HMAC_Init_ex(c.handle.Ptr(), nil, c.digest.handle.Ptr()) {
		return NewOpError("hmac: HMAC_Init_ex(reset)", native.PopError())
	}
	return nil
}

// Close 释放底层句柄。幂等。
// nil 接收者返回 nil；Close 之后所有其他方法返回 "hmac: context closed"。
//
// Close releases the underlying HMAC_CTX. The call is idempotent and
// returns nil on a nil receiver; after Close all other methods on the
// receiver return "hmac: context closed".
func (c *HmacCtx) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}
