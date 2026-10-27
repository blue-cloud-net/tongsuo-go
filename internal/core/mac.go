package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// MAC 表示一个 provider 提供的 MAC 算法描述符（EVP_MAC 的包装）。
// 描述符由本对象拥有，Close 时释放；Close 幂等。
//
// MAC is the Go wrapper around a provider-supplied EVP_MAC descriptor. The
// descriptor is owned by the receiver and released on Close; Close is
// idempotent.
type MAC struct {
	handle *Handle
	name   string
}

// MACFetch 按算法名取 MAC 描述符（如 "CMAC"、"GMAC"、"KMAC-128"、"SIPHASH"、
// "POLY1305"、"EIA3"、"HMAC"）。
// 算法名大小写不敏感（provider 侧按规范名匹配）。
// 名字不可用时返回包装了 OpError 的错误。
//
// MACFetch fetches a MAC descriptor by name (for example "CMAC", "GMAC",
// "KMAC-128", "SIPHASH", "POLY1305", "EIA3" or "HMAC"). The name is
// matched case-insensitively by the provider. An unavailable name yields
// an error wrapping an OpError.
func MACFetch(name string) (*MAC, error) {
	if name == "" {
		return nil, fmt.Errorf("mac: empty algorithm name")
	}
	p := native.EVP_MAC_Fetch(name)
	if p == nil {
		return nil, NewOpError("mac: EVP_MAC_fetch", native.PopError())
	}
	return &MAC{handle: NewHandle(p, true, native.EVP_MAC_Free), name: name}, nil
}

// Name 返回取用该描述符时使用的算法名。
//
// Name returns the algorithm name used to fetch this descriptor.
func (m *MAC) Name() string {
	if m == nil {
		return ""
	}
	return m.name
}

// Close 释放底层 EVP_MAC。幂等。
//
// Close releases the underlying EVP_MAC. The call is idempotent.
func (m *MAC) Close() error {
	if m == nil {
		return nil
	}
	return m.handle.Close()
}

// MACOptions 是一次性 MAC 初始化所需的参数。
// 各算法只取用其中一部分字段；未取用的字段被忽略。
//
// MACOptions carries the parameters needed to initialise a MAC context.
// Each algorithm consumes a subset of the fields; the rest are ignored.
type MACOptions struct {
	// Cipher 是底层分组算法名（CMAC 取 "SM4" / "AES-128" / "AES-192" /
	// "AES-256"；GMAC 取 GCM 模式名如 "AES-128-GCM"）。
	//
	// Cipher selects the underlying block cipher (CMAC: "SM4", "AES-128",
	// "AES-192" or "AES-256"; GMAC: a GCM-mode name such as "AES-128-GCM").
	Cipher string
	// IV 是初始向量（GMAC / EIA3 使用）。
	//
	// IV is the initialization vector (GMAC / EIA3).
	IV []byte
	// AAD 是附加认证数据；初始化后会先于业务数据送入。
	//
	// AAD is the additional authenticated data; it is fed before the
	// payload right after initialisation.
	AAD []byte
	// Custom 是 customization 串（KMAC 使用）。
	//
	// Custom is the customization string (KMAC).
	Custom []byte
	// OutputLen 是输出字节数（KMAC / SipHash 使用；0 表示 provider 默认）。
	//
	// OutputLen is the output size in bytes (KMAC / SipHash; 0 means the
	// provider default).
	OutputLen int
	// Digest 是底层摘要算法名（HMAC 使用，如 "SHA256" / "SM3"）。
	//
	// Digest selects the underlying message-digest name (HMAC, for example
	// "SHA256" or "SM3").
	Digest string
}

// MACCtx 表示一个 MAC 计算上下文（EVP_MAC_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
// 支持流式 Update + Final；Reset 可用相同参数重新初始化后复用。
//
// MACCtx is the Go wrapper around an EVP_MAC_CTX and supports the
// streaming Update + Final interface; Reset re-initialises the context
// with the same parameters so it can be reused. The type owns the
// underlying handle and the caller must invoke Close to release it.
type MACCtx struct {
	handle *Handle
	mac    *MAC
	key    []byte
	opts   MACOptions
	size   int
}

// NewMACCtx 创建并初始化 MAC 上下文。
// opts 为 nil 时使用 provider 默认参数（HMAC 必须给出 Digest）。
// 返回的 *MACCtx 拥有底层 EVP_MAC_CTX，调用方必须调用 Close 释放。
// 描述符为 nil 或已关闭时返回错误 "mac: invalid mac"；初始化失败包装为 OpError。
//
// NewMACCtx creates and initialises a MAC context. A nil opts selects the
// provider defaults (HMAC requires Digest). The returned *MACCtx owns the
// underlying EVP_MAC_CTX and the caller must invoke Close. A nil or
// already-closed descriptor yields the error "mac: invalid mac";
// initialisation failures are wrapped as OpError.
func NewMACCtx(m *MAC, key []byte, opts *MACOptions) (*MACCtx, error) {
	if m == nil || m.handle == nil || m.handle.IsClosed() {
		return nil, fmt.Errorf("mac: invalid mac")
	}
	var o MACOptions
	if opts != nil {
		o = *opts
	}
	ctx := native.EVP_MAC_CTX_New(m.handle.Ptr())
	if ctx == nil {
		return nil, NewOpError("mac: EVP_MAC_CTX_new", native.PopError())
	}
	h := NewHandle(ctx, true, native.EVP_MAC_CTX_Free)
	c := &MACCtx{handle: h, mac: m, key: append([]byte(nil), key...), opts: o}
	if err := c.init(); err != nil {
		_ = h.Close()
		return nil, err
	}
	return c, nil
}

// init 按当前参数初始化上下文（供构造与 Reset 复用）。
//
// init initialises the context with the current parameters (shared by the
// constructor and Reset).
func (c *MACCtx) init() error {
	mask := 0
	if c.opts.Cipher != "" {
		mask |= native.MacOptCipher
	}
	if len(c.opts.IV) > 0 {
		mask |= native.MacOptIV
	}
	if len(c.opts.Custom) > 0 {
		mask |= native.MacOptCustom
	}
	if c.opts.OutputLen > 0 {
		mask |= native.MacOptSize
	}
	if c.opts.Digest != "" {
		mask |= native.MacOptDigest
	}
	if mask != 0 {
		if !native.EVP_MAC_CTX_SetParams(c.handle.Ptr(), mask,
			c.opts.Cipher, c.opts.Digest, c.opts.IV, c.opts.Custom, c.opts.OutputLen) {
			return NewOpError("mac: EVP_MAC_CTX_set_params", native.PopError())
		}
	}
	if !native.EVP_MAC_Init(c.handle.Ptr(), c.key) {
		return NewOpError("mac: EVP_MAC_init", native.PopError())
	}
	if len(c.opts.AAD) > 0 {
		if !native.EVP_MAC_Update(c.handle.Ptr(), c.opts.AAD) {
			return NewOpError("mac: EVP_MAC_update(aad)", native.PopError())
		}
	}
	c.size = native.EVP_MAC_CTX_Size(c.handle.Ptr())
	return nil
}

// Update 追加一段待认证数据。
// 上下文已释放时返回错误 "mac: context closed"；底层失败包装为 OpError。
//
// Update feeds one chunk of data into the MAC computation. The method
// returns the error "mac: context closed" when the context has been
// released; underlying failures are wrapped as OpError.
func (c *MACCtx) Update(data []byte) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("mac: context closed")
	}
	if !native.EVP_MAC_Update(c.handle.Ptr(), data) {
		return NewOpError("mac: EVP_MAC_update", native.PopError())
	}
	return nil
}

// Final 计算并返回 MAC 标签。
// 返回长度为上下文的标签长度（HMAC 等为摘要长度，CMAC/GMAC 为分组长度，
// KMAC/SipHash 为请求的输出长度）。上下文已释放时返回错误 "mac: context closed"。
//
// Final computes and returns the MAC tag. The slice length equals the tag
// size of the context (the digest length for HMAC, the block length for
// CMAC/GMAC, and the requested output length for KMAC/SipHash). The
// method returns the error "mac: context closed" when the context has
// been released.
func (c *MACCtx) Final() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("mac: context closed")
	}
	size := c.size
	if size <= 0 {
		size = native.EVP_MAC_CTX_Size(c.handle.Ptr())
	}
	if size <= 0 {
		return nil, fmt.Errorf("mac: unknown tag size")
	}
	out := make([]byte, size)
	n := native.EVP_MAC_Final(c.handle.Ptr(), out)
	if n == 0 {
		return nil, NewOpError("mac: EVP_MAC_final", native.PopError())
	}
	return out[:n], nil
}

// Sum 返回当前已写入数据的 MAC 标签，不改变上下文状态。
// 内部复制上下文实现，因此 Final 仍可后续调用。
// 上下文已释放时返回错误 "mac: context closed"。
//
// Sum returns the MAC tag of all data written so far without mutating the
// receiver's state. The context is duplicated internally so that Final may
// still be invoked afterwards. The method returns the error "mac: context
// closed" when the context has been released.
func (c *MACCtx) Sum() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("mac: context closed")
	}
	dup := native.EVP_MAC_CTX_Dup(c.handle.Ptr())
	if dup == nil {
		return nil, NewOpError("mac: EVP_MAC_CTX_dup", native.PopError())
	}
	defer native.EVP_MAC_CTX_Free(dup)
	size := c.size
	if size <= 0 {
		size = native.EVP_MAC_CTX_Size(dup)
	}
	if size <= 0 {
		return nil, fmt.Errorf("mac: unknown tag size")
	}
	out := make([]byte, size)
	n := native.EVP_MAC_Final(dup, out)
	if n == 0 {
		return nil, NewOpError("mac: EVP_MAC_final", native.PopError())
	}
	return out[:n], nil
}

// Reset 以相同参数重新初始化上下文，清空已累积的数据。
// 上下文已释放时返回错误 "mac: context closed"；底层失败包装为 OpError。
//
// Reset re-initialises the context with the same parameters, discarding
// the data accumulated so far. The method returns the error "mac: context
// closed" when the context has been released; underlying failures are
// wrapped as OpError.
func (c *MACCtx) Reset() error {
	if c.handle.IsClosed() {
		return fmt.Errorf("mac: context closed")
	}
	return c.init()
}

// Size 返回标签字节长度；上下文未初始化时返回 0。
//
// Size returns the tag size in bytes; it is 0 when the context is not
// initialised.
func (c *MACCtx) Size() int {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return 0
	}
	return c.size
}

// Close 释放底层句柄。幂等。
//
// Close releases the underlying handle. The call is idempotent.
func (c *MACCtx) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}
