package core

import (
	"fmt"
	"runtime"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// FetchCipher 获取由调用方负责 Close 的算法描述符；缺失时返回 nil。
//
// FetchCipher returns an owned descriptor requiring Close, or nil if unavailable.
func FetchCipher(name string) *Cipher { return newCipherOwned(native.EVP_CIPHER_Fetch(name)) }

// NewAEADCtx 创建 OCB 或 SIV 上下文，解密时先设置 tag。
// 调用方负责 Close；底层失败返回 OpError。
//
// NewAEADCtx creates an OCB or SIV context, setting the tag before decryption.
// The caller must Close it; native failures return OpError.
func NewAEADCtx(c *Cipher, key, nonce, tag []byte, enc bool, siv bool) (*CipherCtx, error) {
	defer runtime.KeepAlive(c)
	if c == nil || c.handle.IsClosed() || len(key) != c.KeySize() {
		return nil, fmt.Errorf("cipher: invalid cipher or key")
	}
	ctx := native.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, NewOpError("cipher: new AEAD context", native.PopError())
	}
	h := NewHandle(ctx, true, native.EVP_CIPHER_CTX_free)
	v := native.Decrypt
	if enc {
		v = native.Encrypt
	}
	fail := func(op string) (*CipherCtx, error) {
		err := NewOpError(op, native.PopError())
		h.Close()
		return nil, err
	}
	if !native.EVP_CipherInit_ex(ctx, c.handle.Ptr(), nil, nil, nil, v) {
		return fail("cipher: AEAD init")
	}
	if !siv && !native.EVP_CIPHER_CTX_ctrl(ctx, native.CtrlGCMSetIVLen, len(nonce), nil) {
		return fail("cipher: AEAD nonce length")
	}
	cc := &CipherCtx{handle: h, cipher: c, enc: enc}
	if !enc {
		if err := cc.SetTag(tag); err != nil {
			h.Close()
			return nil, err
		}
	}
	iv := nonce
	if siv {
		iv = nil
	}
	if !native.EVP_CipherInit_ex(ctx, nil, nil, key, iv, v) {
		return fail("cipher: AEAD key init")
	}
	return cc, nil
}
