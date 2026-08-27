package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// HmacCtx 表示一个 HMAC 计算上下文（HMAC_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
type HmacCtx struct {
	handle *Handle
	digest *Digest
}

// NewHmacCtx 创建并初始化 HMAC 上下文（设置密钥与摘要算法）。
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
func (c *HmacCtx) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}
