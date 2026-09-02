package core

import (
	"fmt"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Cipher 表示一个分组加密算法描述符（EVP_CIPHER 的包装）。
// EVP_CIPHER 是铜锁内置常量描述符，不拥有所有权。
//
// Cipher 缓存算法的元数据（分组长度、密钥长度、IV 长度），使构造器无需额外往返 C 库即可完成校验。
//
// Cipher is the Go wrapper around an OpenSSL EVP_CIPHER cipher
// descriptor. The wrapped EVP_CIPHER is a Tongsuo-owned constant object;
// the Cipher does NOT own the underlying pointer (Handle.owned == false)
// and the caller is not required to release it.
//
// Cipher carries the cached metadata of the algorithm (block size, key
// size, IV size) so that constructors can validate them without extra
// round-trips to the C library.
type Cipher struct {
	handle    *Handle
	blockSize int
	keySize   int
	ivSize    int
}

// newCipher 包装算法描述符指针。
//
// newCipher wraps a raw algorithm descriptor pointer into a *Cipher,
// returning nil when c is nil.
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

// SM4ECB 返回 SM4-ECB 分组算法描述符（16 字节分组、16 字节密钥、无 IV，IVSize == 0）。
// ECB 不推荐用于一般场景：相同明文分组会产生相同密文分组。
//
// SM4ECB returns the SM4 block cipher in ECB mode. 16-byte blocks,
// 16-byte key, no IV (IVSize == 0). ECB is NOT recommended for general
// use because identical plaintext blocks yield identical ciphertext.
func SM4ECB() *Cipher { return newCipher(native.EVP_sm4_ecb()) }

// SM4CBC 返回 SM4-CBC 分组算法描述符（16 字节分组、16 字节密钥、16 字节 IV）。
// CBC 要求每次加密使用随机不可预测的 IV，同一密钥下严禁复用 IV。
//
// SM4CBC returns the SM4 block cipher in CBC mode. 16-byte blocks,
// 16-byte key, 16-byte IV. CBC requires a random unpredictable IV per
// encryption; never reuse an IV with the same key.
func SM4CBC() *Cipher { return newCipher(native.EVP_sm4_cbc()) }

// SM4CTR 返回 SM4-CTR 流模式算法描述符（16 字节密钥、16 字节 IV/counter）。
// IV/counter 必须在每个 (key, message) 对中唯一；复用会破坏机密性。
//
// SM4CTR returns the SM4 cipher in CTR mode (treated as a stream
// mode). 16-byte key, 16-byte IV (counter). The IV/counter MUST be
// unique per (key, message) pair; reuse breaks confidentiality.
func SM4CTR() *Cipher { return newCipher(native.EVP_sm4_ctr()) }

// SM4OFB 返回 SM4-OFB 流模式算法描述符（16 字节密钥、16 字节 IV）。
// IV 必须在每个 (key, message) 对中唯一。
//
// SM4OFB returns the SM4 cipher in OFB mode (treated as a stream
// mode). 16-byte key, 16-byte IV. The IV MUST be unique per
// (key, message) pair.
func SM4OFB() *Cipher { return newCipher(native.EVP_sm4_ofb()) }

// SM4CFB 返回 SM4-CFB 流模式算法描述符（CFB128，16 字节密钥、16 字节 IV）。
// IV 必须在每个 (key, message) 对中唯一。
//
// SM4CFB returns the SM4 cipher in CFB128 mode (treated as a stream
// mode). 16-byte key, 16-byte IV. The IV MUST be unique per
// (key, message) pair.
func SM4CFB() *Cipher { return newCipher(native.EVP_sm4_cfb128()) }

// SM4GCM 返回 SM4-GCM 认证加密算法描述符（AEAD，16 字节密钥、可变长度 nonce，推荐 12 字节）。
// nonce 必须在每个 (key, message) 对中唯一；复用会同时破坏机密性与真实性。
//
// SM4GCM returns the SM4 cipher in GCM (AEAD) mode. 16-byte key,
// variable-length nonce (12 bytes recommended). The nonce MUST be
// unique per (key, message) pair; reuse breaks both confidentiality
// and authenticity.
func SM4GCM() *Cipher { return newCipher(native.EVP_sm4_gcm()) }

// AES128ECB 返回 AES-128-ECB 分组算法描述符（16 字节分组、16 字节密钥、无 IV，IVSize == 0）。
// ECB 不推荐用于一般场景。
//
// AES128ECB returns AES-128 in ECB mode. 16-byte blocks, 16-byte key,
// no IV (IVSize == 0). ECB is NOT recommended for general use.
func AES128ECB() *Cipher { return newCipher(native.EVP_aes_128_ecb()) }

// AES128CBC 返回 AES-128-CBC 分组算法描述符（16 字节分组、16 字节密钥、16 字节 IV）。
// CBC 要求每次加密使用随机不可预测的 IV，同一密钥下严禁复用 IV。
//
// AES128CBC returns AES-128 in CBC mode. 16-byte blocks, 16-byte key,
// 16-byte IV. CBC requires a random unpredictable IV per encryption;
// never reuse an IV with the same key.
func AES128CBC() *Cipher { return newCipher(native.EVP_aes_128_cbc()) }

// AES128CTR 返回 AES-128-CTR 流模式算法描述符（16 字节密钥、16 字节 IV/counter）。
// IV/counter 必须在每个 (key, message) 对中唯一；复用会破坏机密性。
//
// AES128CTR returns AES-128 in CTR mode (treated as a stream mode).
// 16-byte key, 16-byte IV (counter). The IV/counter MUST be unique
// per (key, message) pair; reuse breaks confidentiality.
func AES128CTR() *Cipher { return newCipher(native.EVP_aes_128_ctr()) }

// AES128GCM 返回 AES-128-GCM 认证加密算法描述符（AEAD，16 字节密钥、可变长度 nonce，推荐 12 字节）。
// nonce 必须在每个 (key, message) 对中唯一；复用会同时破坏机密性与真实性。
//
// AES128GCM returns AES-128 in GCM (AEAD) mode. 16-byte key,
// variable-length nonce (12 bytes recommended). The nonce MUST be
// unique per (key, message) pair; reuse breaks both confidentiality
// and authenticity.
func AES128GCM() *Cipher { return newCipher(native.EVP_aes_128_gcm()) }

// AES256ECB 返回 AES-256-ECB 分组算法描述符（16 字节分组、32 字节密钥、无 IV，IVSize == 0）。
// ECB 不推荐用于一般场景。
//
// AES256ECB returns AES-256 in ECB mode. 16-byte blocks, 32-byte key,
// no IV (IVSize == 0). ECB is NOT recommended for general use.
func AES256ECB() *Cipher { return newCipher(native.EVP_aes_256_ecb()) }

// AES256CBC 返回 AES-256-CBC 分组算法描述符（16 字节分组、32 字节密钥、16 字节 IV）。
// CBC 要求每次加密使用随机不可预测的 IV，同一密钥下严禁复用 IV。
//
// AES256CBC returns AES-256 in CBC mode. 16-byte blocks, 32-byte key,
// 16-byte IV. CBC requires a random unpredictable IV per encryption;
// never reuse an IV with the same key.
func AES256CBC() *Cipher { return newCipher(native.EVP_aes_256_cbc()) }

// AES256CTR 返回 AES-256-CTR 流模式算法描述符（32 字节密钥、16 字节 IV/counter）。
// IV/counter 必须在每个 (key, message) 对中唯一；复用会破坏机密性。
//
// AES256CTR returns AES-256 in CTR mode (treated as a stream mode).
// 32-byte key, 16-byte IV (counter). The IV/counter MUST be unique
// per (key, message) pair; reuse breaks confidentiality.
func AES256CTR() *Cipher { return newCipher(native.EVP_aes_256_ctr()) }

// AES256GCM 返回 AES-256-GCM 认证加密算法描述符（AEAD，32 字节密钥、可变长度 nonce，推荐 12 字节）。
// nonce 必须在每个 (key, message) 对中唯一；复用会同时破坏机密性与真实性。
//
// AES256GCM returns AES-256 in GCM (AEAD) mode. 32-byte key,
// variable-length nonce (12 bytes recommended). The nonce MUST be
// unique per (key, message) pair; reuse breaks both confidentiality
// and authenticity.
func AES256GCM() *Cipher { return newCipher(native.EVP_aes_256_gcm()) }

// BlockSize 返回分组长度（字节），例如 SM4/AES 为 16。
//
// BlockSize returns the cipher's block size in bytes (16 for SM4/AES).
func (c *Cipher) BlockSize() int { return c.blockSize }

// KeySize 返回密钥长度（字节），例如 SM4/AES-128 为 16、AES-256 为 32。
//
// KeySize returns the cipher's key length in bytes (16 for SM4/AES-128,
// 32 for AES-256).
func (c *Cipher) KeySize() int { return c.keySize }

// IVSize 返回 IV 长度（字节）；ECB 等无 IV 模式为 0。
// ECB 等不消耗 IV 的模式返回 0；SM4/AES 的 CBC/CTR/OFB/CFB 返回 16；
// GCM 在描述符层返回 0（nonce 长度通过 NewGcmCtx 或 SetIVLength 按上下文配置）。
//
// IVSize returns the cipher's IV length in bytes. ECB and other modes
// that do not consume an IV return 0; CBC/CTR/OFB/CFB return 16 for
// SM4/AES; GCM returns 0 at the descriptor level (the nonce length is
// configured per-context via NewGcmCtx or SetIVLength).
func (c *Cipher) IVSize() int { return c.ivSize }

// CipherCtx 表示一个加密/解密上下文（EVP_CIPHER_CTX 的包装）。
// 使用完毕必须调用 Close 释放底层句柄。
// 类型支持流式接口（Update + Final）以及一次性便捷函数 EncryptAll/DecryptAll；通过内部 Handle 拥有底层 EVP_CIPHER_CTX。
//
// CipherCtx is the Go wrapper around an OpenSSL EVP_CIPHER_CTX and
// supports the streaming cipher interface (Update + Final) as well as
// the one-shot EncryptAll/DecryptAll helpers. The type owns the
// underlying EVP_CIPHER_CTX through an internal Handle and the caller
// MUST invoke Close to release it once done.
type CipherCtx struct {
	handle *Handle
	cipher *Cipher
	enc    bool
	pad    bool
}

// NewCipherCtx 创建并初始化加密/解密上下文。
// enc == true 选加密，enc == false 选解密；key 长度必须为 Cipher.KeySize；iv 长度必须为 Cipher.IVSize（无 IV 模式如 ECB 可传 nil）。
// 默认启用 PKCS#7 填充，可通过 SetPadding 关闭；返回的 *CipherCtx 拥有底层 EVP_CIPHER_CTX，调用方必须调用 Close。
// c 为 nil 或句柄已关闭返回 "cipher: invalid cipher"；key / iv 长度不匹配返回 "cipher: key length %d, want %d" 或 "cipher: iv length %d, want %d"；底层 OpenSSL 失败包装为 OpError。
//
// NewCipherCtx creates and initialises a cipher context for the
// algorithm described by c. enc == true selects encryption, enc == false
// selects decryption. key MUST have length Cipher.KeySize; iv MUST have
// length Cipher.IVSize (and MAY be nil for IV-less modes such as ECB).
// PKCS#7 padding is enabled by default and may be toggled via
// SetPadding. The returned *CipherCtx owns the underlying
// EVP_CIPHER_CTX and the caller MUST invoke Close. Returns
// "cipher: invalid cipher" when c is nil or its handle is closed,
// "cipher: key length %d, want %d" / "cipher: iv length %d, want %d"
// for mismatched sizes, or a wrapped OpError when the underlying
// OpenSSL call fails.
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
// pad == false 时调用方必须保证输入长度为 Cipher.BlockSize 的整数倍；上下文已释放返回 "cipher: context closed"，底层 OpenSSL 失败包装为 OpError。
//
// SetPadding enables or disables PKCS#7 padding. pad == true enables
// PKCS#7 padding; pad == false disables it (callers MUST then supply
// input whose length is a multiple of Cipher.BlockSize). Returns
// "cipher: context closed" when the context has been released;
// underlying OpenSSL failures are wrapped as OpError.
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
// 加密路径上只调用 Update 而不调用 Final 会使尾部填充块未发出；解密路径上未调用 Final 时尾部块将不会被校验。
// 上下文已释放返回 "cipher: context closed"，底层 OpenSSL 失败包装为 OpError。
//
// Update feeds one chunk of input to the cipher and returns the
// ciphertext or plaintext bytes produced for that chunk. The full
// processing flow is Update followed by Final; calling Update without
// a Final on an encrypt path will leave the trailing padding block
// un-emitted, and on a decrypt path will leave the trailing block
// un-verified. Returns "cipher: context closed" when the context has
// been released; underlying OpenSSL failures are wrapped as OpError.
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
// 加密路径返回（可能含填充的）尾部块；解密路径在校验 PKCS#7 填充后返回最后解密的字节（坏填充报告为 OpError）。必须在 Update 之后、Close 之前调用。
// 上下文已释放返回 "cipher: context closed"。
//
// Final flushes any internally buffered bytes and returns the trailing
// block: on the encrypt path the (possibly padded) final block; on the
// decrypt path the last decrypted bytes after PKCS#7 padding has been
// validated (a bad padding is reported as OpError). Must be called
// after Update(s) and before Close. Returns "cipher: context closed"
// when the context has been released.
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

// EncryptAll 一次性加密全部数据（Update + Final），将输出拼接后返回。调用方仍负责调用 Close。
//
// EncryptAll is a convenience wrapper that performs Update followed by
// Final on the encryption path and concatenates their output. The
// caller is still responsible for invoking Close.
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

// DecryptAll 一次性解密全部数据（Update + Final，含填充校验），将输出拼接后返回。
// 尾部 PKCS#7 填充块由 Final 校验，密文被篡改将报告为 OpError。调用方仍负责调用 Close。
//
// DecryptAll is a convenience wrapper that performs Update followed by
// Final on the decryption path and concatenates their output. The
// trailing PKCS#7 padding block is verified as part of Final and a
// tampered ciphertext is reported as OpError. The caller is still
// responsible for invoking Close.
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
// nil 接收者返回 nil；Close 之后所有其他方法返回 "cipher: context closed"。
//
// Close releases the underlying EVP_CIPHER_CTX. The call is idempotent
// and returns nil on a nil receiver; after Close all other methods on
// the receiver return "cipher: context closed".
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
// enc == true 选加密，enc == false 选解密。cipher c 必须是 GCM 描述符（如 SM4GCM、AES128GCM、AES256GCM）；
// key 长度必须为 Cipher.KeySize；nonce 可为任意非空长度（推荐 12 字节 / 96 位）；不应用 PKCS#7 填充（pad 被强制为 false）。
// 返回的 *CipherCtx 拥有底层 EVP_CIPHER_CTX，调用方必须调用 Close。
// c 为 nil 或句柄已关闭返回 "cipher: invalid cipher"；key 长度不匹配返回 "cipher: key length %d, want %d"；
// nonce 长度为 0 返回 "cipher: empty nonce"；底层 OpenSSL 调用失败包装为 OpError。
//
// NewGcmCtx creates a GCM (AEAD) cipher context using the documented
// three-step sequence:
//
//  1. EVP_CipherInit_ex(ctx, cipher, nil, key, nil, enc) sets the
//     algorithm and key (no IV yet).
//  2. EVP_CIPHER_CTX_ctrl(ctx, SET_IVLEN, len(nonce), nil) sets the
//     nonce length to len(nonce).
//  3. EVP_CipherInit_ex(ctx, nil, nil, nil, nonce, enc) sets the nonce.
//
// enc == true selects encryption, enc == false selects decryption. The
// cipher c MUST be a GCM descriptor (e.g. SM4GCM, AES128GCM,
// AES256GCM). key MUST have length Cipher.KeySize. nonce MAY be any
// non-empty length; 12 bytes (96 bits) is recommended. PKCS#7 padding
// is not applied (pad is forced to false). The returned *CipherCtx
// owns the underlying EVP_CIPHER_CTX and the caller MUST invoke
// Close. Returns "cipher: invalid cipher" when c is nil or its handle
// is closed, "cipher: key length %d, want %d" for mismatched key,
// "cipher: empty nonce" for a zero-length nonce, or a wrapped OpError
// when the underlying OpenSSL call fails.
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
// 必须在任何 Update/EncryptAll/DecryptAll 之前调用；底层为标准的 SET_IVLEN ctrl。
// 上下文已释放返回 "cipher: context closed"，底层 OpenSSL 失败包装为 OpError。
//
// SetIVLength reconfigures the GCM nonce/IV length for the receiver.
// It MUST be called before any Update/EncryptAll/DecryptAll call;
// the underlying OpenSSL call is the standard SET_IVLEN ctrl on
// EVP_CIPHER_CTX. Returns "cipher: context closed" when the context has
// been released; underlying OpenSSL failures are wrapped as OpError.
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
// 解密时必须传入与加密时完全一致的 AAD（逐字节相同），否则 Final 中的标签校验将失败。
// 底层调用按构造时的方向分别路由到 EVP_EncryptUpdate / EVP_DecryptUpdate。
// 上下文已释放返回 "cipher: context closed"；OpenSSL 失败包装为 OpError。
//
// SetAad supplies Additional Authenticated Data (AAD) to the GCM
// context. AAD participates in the authentication tag but is NOT
// emitted as ciphertext. The AAD supplied on the decrypt path MUST be
// byte-for-byte identical to the one supplied on the encrypt path,
// otherwise the tag check in Final will fail. The underlying call
// dispatches to EVP_EncryptUpdate / EVP_DecryptUpdate depending on the
// direction selected at construction time. Returns "cipher: context
// closed" when the context has been released; OpenSSL failures are
// wrapped as OpError.
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
// tag 缓冲区必须按期望的标签长度分配（通常 16 字节），按 in-place 填充。
// 上下文已释放返回 "cipher: context closed"；零长度切片返回 "cipher: empty tag buffer"；底层 ctrl 失败包装为 OpError。
//
// GetTag retrieves the GCM authentication tag after Final has been
// called on the encrypt path. The tag buffer MUST be sized to the
// expected tag length (typically 16 bytes); the buffer is filled in
// place. Returns "cipher: context closed" when the context has been
// released, "cipher: empty tag buffer" for a zero-length slice, or a
// wrapped OpError when the underlying ctrl fails.
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
// tag 必须与加密侧产生的标签匹配；不匹配将导致 Final 报告认证失败（包装为 OpError）。
// 上下文已释放返回 "cipher: context closed"；零长度切片返回 "cipher: empty tag"；底层 ctrl 失败包装为 OpError。
//
// SetTag supplies the expected GCM authentication tag on the decrypt
// path before Final is called. The tag MUST match the one produced by
// the encrypt side; a mismatch causes Final to report an
// authentication failure (wrapped as OpError). Returns
// "cipher: context closed" when the context has been released,
// "cipher: empty tag" for a zero-length slice, or a wrapped OpError
// when the underlying ctrl fails.
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
