package core

import (
	"fmt"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Cipher 表示一个分组加密算法描述符（EVP_CIPHER 的包装）。
// EVP_CIPHER 是铜锁内置常量描述符，不拥有所有权。
type Cipher struct {
	handle    *Handle
	blockSize int
	keySize   int
	ivSize    int
}

// newCipher 包装算法描述符指针。
func newCipher(c unsafe.Pointer) *Cipher {
	if c == nil {
		return nil
	}
	return &Cipher{
		handle:    NewHandle(c, false, nil),
		blockSize: native.EVP_CIPHER_get_block_size(c),
		keySize:   native.EVP_CIPHER_get_key_length(c),
		ivSize:    native.EVP_CIPHER_get_iv_length(c),
	}
}

// SM4ECB 返回 SM4-ECB 分组算法描述符。
func SM4ECB() *Cipher { return newCipher(native.EVP_sm4_ecb()) }

// SM4CBC 返回 SM4-CBC 分组算法描述符。
func SM4CBC() *Cipher { return newCipher(native.EVP_sm4_cbc()) }

// SM4CTR 返回 SM4-CTR 流模式算法描述符。
func SM4CTR() *Cipher { return newCipher(native.EVP_sm4_ctr()) }

// SM4OFB 返回 SM4-OFB 流模式算法描述符。
func SM4OFB() *Cipher { return newCipher(native.EVP_sm4_ofb()) }

// SM4CFB 返回 SM4-CFB 流模式算法描述符。
func SM4CFB() *Cipher { return newCipher(native.EVP_sm4_cfb128()) }

// SM4GCM 返回 SM4-GCM 认证加密算法描述符（AEAD）。
func SM4GCM() *Cipher { return newCipher(native.EVP_sm4_gcm()) }

// AES128ECB 返回 AES-128-ECB 分组算法描述符。
func AES128ECB() *Cipher { return newCipher(native.EVP_aes_128_ecb()) }

// AES128CBC 返回 AES-128-CBC 分组算法描述符。
func AES128CBC() *Cipher { return newCipher(native.EVP_aes_128_cbc()) }

// AES128CTR 返回 AES-128-CTR 流模式算法描述符。
func AES128CTR() *Cipher { return newCipher(native.EVP_aes_128_ctr()) }

// AES128GCM 返回 AES-128-GCM 认证加密算法描述符（AEAD）。
func AES128GCM() *Cipher { return newCipher(native.EVP_aes_128_gcm()) }

// AES256ECB 返回 AES-256-ECB 分组算法描述符。
func AES256ECB() *Cipher { return newCipher(native.EVP_aes_256_ecb()) }

// AES256CBC 返回 AES-256-CBC 分组算法描述符。
func AES256CBC() *Cipher { return newCipher(native.EVP_aes_256_cbc()) }

// AES256CTR 返回 AES-256-CTR 流模式算法描述符。
func AES256CTR() *Cipher { return newCipher(native.EVP_aes_256_ctr()) }

// AES256GCM 返回 AES-256-GCM 认证加密算法描述符（AEAD）。
func AES256GCM() *Cipher { return newCipher(native.EVP_aes_256_gcm()) }

// BlockSize 返回分组长度（字节）。
func (c *Cipher) BlockSize() int { return c.blockSize }

// KeySize 返回密钥长度（字节）。
func (c *Cipher) KeySize() int { return c.keySize }

// IVSize 返回 IV 长度（字节）；ECB 等无 IV 模式为 0。
func (c *Cipher) IVSize() int { return c.ivSize }

// CipherCtx 表示一个加密/解密上下文（EVP_CIPHER_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
type CipherCtx struct {
	handle *Handle
	cipher *Cipher
	enc    bool
	pad    bool
}

// NewCipherCtx 创建并初始化加密/解密上下文。
// enc 为 true 表示加密，false 表示解密；iv 在无 IV 模式（如 ECB）下传 nil。
// 默认启用 PKCS7 填充，可通过 SetPadding 关闭。
func NewCipherCtx(c *Cipher, key, iv []byte, enc bool) (*CipherCtx, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("cipher: invalid cipher")
	}
	if len(key) != c.keySize {
		return nil, fmt.Errorf("cipher: key length %d, want %d", len(key), c.keySize)
	}
	if c.ivSize > 0 && len(iv) != c.ivSize {
		return nil, fmt.Errorf("cipher: iv length %d, want %d", len(iv), c.ivSize)
	}
	ctx := native.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, NewOpError("cipher: EVP_CIPHER_CTX_new", native.PopError())
	}
	h := NewHandle(ctx, true, native.EVP_CIPHER_CTX_free)
	encv := native.Decrypt
	if enc {
		encv = native.Encrypt
	}
	if !native.EVP_CipherInit_ex(ctx, c.handle.Ptr(), nil, key, iv, encv) {
		_ = h.Close()
		return nil, NewOpError("cipher: EVP_CipherInit_ex", native.PopError())
	}
	return &CipherCtx{handle: h, cipher: c, enc: enc, pad: true}, nil
}

// SetPadding 设置填充模式（true=PKCS7，false=无填充）。
func (c *CipherCtx) SetPadding(pad bool) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("cipher: context closed")
	}
	v := 0
	if pad {
		v = 1
	}
	if !native.EVP_CIPHER_CTX_set_padding(c.handle.Ptr(), v) {
		return NewOpError("cipher: EVP_CIPHER_CTX_set_padding", native.PopError())
	}
	c.pad = pad
	return nil
}

// Update 处理一段数据，返回本段输出。完整流程为 Update + Final。
func (c *CipherCtx) Update(in []byte) ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("cipher: context closed")
	}
	out := make([]byte, len(in)+c.cipher.BlockSize())
	var outl int
	var ok bool
	if c.enc {
		ok = native.EVP_EncryptUpdate(c.handle.Ptr(), out, in, &outl)
	} else {
		ok = native.EVP_DecryptUpdate(c.handle.Ptr(), out, in, &outl)
	}
	if !ok {
		return nil, NewOpError("cipher: Update", native.PopError())
	}
	return out[:outl], nil
}

// Final 结束处理，返回剩余输出（含填充块或填充校验）。
func (c *CipherCtx) Final() ([]byte, error) {
	if c.handle.IsClosed() {
		return nil, fmt.Errorf("cipher: context closed")
	}
	out := make([]byte, c.cipher.BlockSize())
	var outl int
	var ok bool
	if c.enc {
		ok = native.EVP_EncryptFinal_ex(c.handle.Ptr(), out, &outl)
	} else {
		ok = native.EVP_DecryptFinal_ex(c.handle.Ptr(), out, &outl)
	}
	if !ok {
		return nil, NewOpError("cipher: Final", native.PopError())
	}
	return out[:outl], nil
}

// EncryptAll 一次性加密全部数据（Update + Final）。
func (c *CipherCtx) EncryptAll(in []byte) ([]byte, error) {
	part1, err := c.Update(in)
	if err != nil {
		return nil, err
	}
	part2, err := c.Final()
	if err != nil {
		return nil, err
	}
	return append(part1, part2...), nil
}

// DecryptAll 一次性解密全部数据（Update + Final，含填充校验）。
func (c *CipherCtx) DecryptAll(in []byte) ([]byte, error) {
	part1, err := c.Update(in)
	if err != nil {
		return nil, err
	}
	part2, err := c.Final()
	if err != nil {
		return nil, err
	}
	return append(part1, part2...), nil
}

// Close 释放底层句柄。幂等。
func (c *CipherCtx) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// NewGcmCtx 以 GCM 两步初始化方式创建加密/解密上下文。
//
// 序列（经验证，与官方 tongsuo-go-sdk 一致）：
//  1. EVP_CipherInit_ex(ctx, cipher, nil, key, nil, enc)  设置算法与密钥
//  2. EVP_CIPHER_CTX_ctrl(ctx, SET_IVLEN, len(nonce), nil) 设置 nonce 长度
//  3. EVP_CipherInit_ex(ctx, nil, nil, nil, nonce, enc)    设置 nonce
//
// nonce 推荐 12 字节（96 位）。
func NewGcmCtx(c *Cipher, key, nonce []byte, enc bool) (*CipherCtx, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("cipher: invalid cipher")
	}
	if len(key) != c.keySize {
		return nil, fmt.Errorf("cipher: key length %d, want %d", len(key), c.keySize)
	}
	if len(nonce) == 0 {
		return nil, fmt.Errorf("cipher: empty nonce")
	}
	ctx := native.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, NewOpError("cipher: EVP_CIPHER_CTX_new", native.PopError())
	}
	h := NewHandle(ctx, true, native.EVP_CIPHER_CTX_free)
	encv := native.Decrypt
	if enc {
		encv = native.Encrypt
	}
	// 第一步：设置算法与密钥（iv 暂不设置）。
	if !native.EVP_CipherInit_ex(ctx, c.handle.Ptr(), nil, key, nil, encv) {
		_ = h.Close()
		return nil, NewOpError("cipher: EVP_CipherInit_ex(cipher,key)", native.PopError())
	}
	// 第二步：设置 nonce 长度。
	if !native.EVP_CIPHER_CTX_ctrl(ctx, native.CtrlGCMSetIVLen, len(nonce), nil) {
		_ = h.Close()
		return nil, NewOpError("cipher: EVP_CIPHER_CTX_ctrl(SET_IVLEN)", native.PopError())
	}
	// 第三步：仅设置 nonce。
	if !native.EVP_CipherInit_ex(ctx, nil, nil, nil, nonce, encv) {
		_ = h.Close()
		return nil, NewOpError("cipher: EVP_CipherInit_ex(iv)", native.PopError())
	}
	return &CipherCtx{handle: h, cipher: c, enc: enc, pad: false}, nil
}

// SetIVLength 设置 GCM IV/Nonce 长度（创建上下文前调整）。
func (c *CipherCtx) SetIVLength(n int) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("cipher: context closed")
	}
	if !native.EVP_CIPHER_CTX_ctrl(c.handle.Ptr(), native.CtrlGCMSetIVLen, n, nil) {
		return NewOpError("cipher: EVP_CIPHER_CTX_ctrl(SET_IVLEN)", native.PopError())
	}
	return nil
}

// SetAad 设置附加认证数据（AAD），仅参与认证不参与加密。
// 解密时必须传入与加密时完全一致的 AAD。
// 注意：加密/解密上下文分别使用 EVP_EncryptUpdate / EVP_DecryptUpdate 喂 AAD。
func (c *CipherCtx) SetAad(aad []byte) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("cipher: context closed")
	}
	if !native.EVP_UpdateAAD(c.handle.Ptr(), aad, c.enc) {
		return NewOpError("cipher: EVP_UpdateAAD", native.PopError())
	}
	return nil
}

// GetTag 获取 GCM 认证标签（加密流程，Final 之后调用）。
func (c *CipherCtx) GetTag(tag []byte) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("cipher: context closed")
	}
	if len(tag) == 0 {
		return fmt.Errorf("cipher: empty tag buffer")
	}
	if !native.EVP_CIPHER_CTX_ctrl(c.handle.Ptr(), native.CtrlGCMGetTag,
		len(tag), unsafe.Pointer(&tag[0])) {
		return NewOpError("cipher: EVP_CIPHER_CTX_ctrl(GET_TAG)", native.PopError())
	}
	return nil
}

// SetTag 设置 GCM 认证标签（解密流程，Final 之前调用）。
func (c *CipherCtx) SetTag(tag []byte) error {
	if c.handle.IsClosed() {
		return fmt.Errorf("cipher: context closed")
	}
	if len(tag) == 0 {
		return fmt.Errorf("cipher: empty tag")
	}
	if !native.EVP_CIPHER_CTX_ctrl(c.handle.Ptr(), native.CtrlGCMSetTag,
		len(tag), unsafe.Pointer(&tag[0])) {
		return NewOpError("cipher: EVP_CIPHER_CTX_ctrl(SET_TAG)", native.PopError())
	}
	return nil
}
