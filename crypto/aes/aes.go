// Package aes 基于铜锁原生实现实现 AES 分组加密（128 / 256 位）。
// 提供标准库 cipher.Block 接口（NewCipher）、一次性便捷函数
// （EncryptECB / EncryptCBC / EncryptCTR / EncryptGCM 等）以及 AEAD 接口（NewGCM）；
// 密钥长度必须为 16 字节（AES-128）或 32 字节（AES-256），其它长度返回错误，
// ECB 仅作为兼容保留，禁止用于新协议。
//
// Package aes provides AES (128 / 256 bit) block-cipher primitives backed by
// the Tongsuo native library. It exposes the standard library cipher.Block
// interface (NewCipher), one-shot helpers (EncryptECB / EncryptCBC / EncryptCTR
// / EncryptGCM and their Decrypt counterparts) and an AEAD interface (NewGCM).
// Key lengths must be exactly 16 bytes (AES-128) or 32 bytes (AES-256); any
// other length returns an error. ECB is intentionally exposed for
// compatibility only and must not be used for new protocols.
package aes

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// BlockSize 为 AES 分组长度（字节）。
//
// BlockSize is the AES block size in bytes and is always 16, independent of
// the key length (128 or 256 bit).
const BlockSize = 16

// gcm 相关常量（NonceSize / TagSize）。
//
// gcm-related constants: NonceSize and TagSize.
const (
	// NonceSize 为 AES-GCM 推荐的 Nonce 长度（96 位）。
	//
	// NonceSize is the recommended AES-GCM nonce length in bytes (96 bits).
	NonceSize = 12
	// TagSize 为 AES-GCM 认证标签长度（128 位）。
	//
	// TagSize is the AES-GCM authentication tag length in bytes (128 bits).
	TagSize = 16
)

// aesCipher 根据密钥长度选择对应 AES 算法描述符。
// mode 取 "ecb" / "cbc" / "ctr" / "gcm"。
//
// aesCipher selects the Tongsuo AES descriptor for the given key size and
// mode string ("ecb", "cbc", "ctr", "gcm"). It returns an error if the key
// length is not 16 (AES-128) or 32 (AES-256).
func aesCipher(key []byte, mode string) (*core.Cipher, error) {
	var c *core.Cipher
	switch len(key) {
	case 16:
		switch mode {
		case "ecb":
			c = core.AES128ECB()
		case "cbc":
			c = core.AES128CBC()
		case "ctr":
			c = core.AES128CTR()
		case "gcm":
			c = core.AES128GCM()
		}
	case 32:
		switch mode {
		case "ecb":
			c = core.AES256ECB()
		case "cbc":
			c = core.AES256CBC()
		case "ctr":
			c = core.AES256CTR()
		case "gcm":
			c = core.AES256GCM()
		}
	default:
		return nil, fmt.Errorf("aes: invalid key size %d, want 16 or 32", len(key))
	}
	return c, nil
}

func newNoPadCtx(key []byte, c *core.Cipher, enc bool) (*core.CipherCtx, error) {
	ctx, err := core.NewCipherCtx(c, key, nil, enc)
	if err != nil {
		return nil, err
	}
	if err := ctx.SetPadding(false); err != nil {
		_ = ctx.Close()
		return nil, err
	}
	return ctx, nil
}

// aesBlock 是基于铜锁 EVP 的 AES 单块加密封装，实现 cipher.Block。
//
// aesBlock 持有两个不可变的"模板"上下文（encTpl/decTpl），从未调用 Update；
// 每次 Encrypt/Decrypt 都通过 EVP_CIPHER_CTX_copy 复制模板得到独立的副
// 本，并在副本上调 Update——这样 Block 实例可被多个 goroutine 并发复用，
// 与 Go 标准库 cipher.Block 的并发安全契约对齐。
//
// aesBlock implements cipher.Block for AES.
//
// The type keeps two untouched "template" contexts (encTpl/decTpl)
// built from the original key. Every Encrypt/Decrypt call deep-copies
// the template via EVP_CIPHER_CTX_copy and operates on the copy, so
// the same Block can be safely shared across goroutines — matching
// the concurrency contract of Go's stdlib cipher.Block.
type aesBlock struct {
	encTpl *core.CipherCtx // ECB / 无填充，加密模板（永不在其上调 Update）
	decTpl *core.CipherCtx // ECB / 无填充，解密模板（永不在其上调 Update）
}

// NewCipher 返回使用给定密钥的 AES 分组加密器（cipher.Block）。
// key 必须为 16（AES-128）或 32（AES-256）字节。
//
// 返回的 Block 仅执行裸 16 字节分组变换，不做填充、不使用 IV；在上层链式模式
// （CBC、CTR ...）中由调用方自行提供 IV。
// 同一 Block 实例可被多个 goroutine 并发复用（与 stdlib 一致）。
//
// NewCipher returns an AES cipher.Block configured with the given key.
//
// key must be exactly 16 bytes (AES-128) or 32 bytes (AES-256); any other
// length returns an error. The returned Block performs raw 16-byte block
// transforms with no padding and no IV; callers supply an IV themselves
// when chaining it in a higher-level mode (CBC, CTR, ...). The same
// Block is safe for concurrent use by multiple goroutines.
func NewCipher(key []byte) (cipher.Block, error) {
	c, err := aesCipher(key, "ecb")
	if err != nil {
		return nil, err
	}
	encTpl, err := newNoPadCtx(key, c, true)
	if err != nil {
		return nil, err
	}
	decTpl, err := newNoPadCtx(key, c, false)
	if err != nil {
		_ = encTpl.Close()
		return nil, err
	}
	return &aesBlock{encTpl: encTpl, decTpl: decTpl}, nil
}

// Encrypt 加密一个分组（16 字节）。
// 若 dst 或 src 长度不足 16 字节，或底层 EVP 计算失败，会 panic。
//
// 内部从加密模板 EVP_CIPHER_CTX_copy 一份独立副本并立即调 Update+Close，
// 保证模板不被并发调用方共享。
//
// 分组密码本身不提供完整性保护；需要认证加密时请使用 AEAD 模式（GCM）。
//
// Encrypt encrypts a single AES block (16 bytes) from src into dst.
//
// It panics if len(dst) < 16, len(src) < 16, or the underlying EVP call
// fails. Internally the call copies the encryption template via
// EVP_CIPHER_CTX_copy and runs Update on the independent copy, so
// concurrent goroutines each see their own context.
//
// The block cipher does not provide integrity protection on its own;
// prefer an AEAD mode (GCM) for authenticated encryption.
func (b *aesBlock) Encrypt(dst, src []byte) {
	if len(dst) < BlockSize || len(src) < BlockSize {
		panic("aes: invalid block size")
	}
	ctx, err := b.encTpl.Clone()
	if err != nil {
		panic(err)
	}
	defer ctx.Close()
	out, err := ctx.Update(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst[:BlockSize], out)
}

// Decrypt 解密一个分组（16 字节），若 dst 或 src 长度不足 16 字节，或底层 EVP 计算失败，会 panic。
//
// 内部从解密模板 EVP_CIPHER_CTX_copy 一份独立副本并立即调 Update+Close。
//
// Decrypt decrypts a single AES block (16 bytes) from src into dst; it panics if len(dst) < 16, len(src) < 16, or the underlying EVP call fails. Internally the call copies the decryption template via EVP_CIPHER_CTX_copy and runs Update on the independent copy.
func (b *aesBlock) Decrypt(dst, src []byte) {
	if len(dst) < BlockSize || len(src) < BlockSize {
		panic("aes: invalid block size")
	}
	ctx, err := b.decTpl.Clone()
	if err != nil {
		panic(err)
	}
	defer ctx.Close()
	out, err := ctx.Update(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst[:BlockSize], out)
}

// BlockSize 返回分组长度，始终为 BlockSize（16）字节。
//
// BlockSize returns the AES block size in bytes, always BlockSize (16).
func (b *aesBlock) BlockSize() int { return BlockSize }

// EncryptECB 使用 AES-ECB 加密 data（PKCS7 填充）。
// key 必须为 16（AES-128）或 32（AES-256）字节；其它长度返回错误。
//
// ECB 会泄露明文重复模式，禁止用于新协议；本函数仅用于遗留数据兼容。
//
// EncryptECB encrypts data with AES-ECB (PKCS#7 padding).
//
// key must be exactly 16 bytes (AES-128) or 32 bytes (AES-256); any other
// length returns an error. ECB leaks plaintext repetition patterns and
// must not be used in new protocols; this helper exists only for legacy
// data compatibility.
func EncryptECB(key, data []byte) ([]byte, error) {
	return cryptAll(key, nil, data, true, "ecb")
}

// DecryptECB 使用 AES-ECB 解密 data（PKCS7 填充）。
// key 必须为 16（AES-128）或 32（AES-256）字节；其它长度或 PKCS7 填充错误返回错误。
//
// DecryptECB decrypts data with AES-ECB (PKCS#7 padding). key must be
// exactly 16 bytes (AES-128) or 32 bytes (AES-256); any other length, or
// corrupted PKCS#7 padding, returns an error.
func DecryptECB(key, data []byte) ([]byte, error) {
	return cryptAll(key, nil, data, false, "ecb")
}

// EncryptCBC 使用 AES-CBC 加密 data（PKCS7 填充），iv 长度必须为 BlockSize。
// iv 必须为 BlockSize 字节且在每个 (key, message) 对下唯一不可预测——推荐使用
// crypto/rand 生成随机 IV。CBC 不提供完整性保护，建议搭配 HMAC 使用或直接选择 AES-GCM。
//
// EncryptCBC encrypts data with AES-CBC (PKCS#7 padding). iv must be exactly
// BlockSize bytes and must be unpredictable and unique per (key, message)
// pair — use a random IV from crypto/rand. CBC does not provide integrity
// protection; pair it with an HMAC or prefer AES-GCM.
func EncryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, "cbc")
}

// DecryptCBC 使用 AES-CBC 解密 data（PKCS7 填充），iv 须与加密时一致。
// iv 长度必须为 BlockSize；填充错误或底层失败返回错误。
//
// DecryptCBC decrypts data with AES-CBC (PKCS#7 padding). iv must be
// exactly BlockSize bytes and must match the IV used during encryption.
// Corrupted PKCS#7 padding or any underlying EVP failure returns an
// error.
func DecryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, "cbc")
}

// EncryptCTR 使用 AES-CTR 加密 data（流模式，无填充）。iv 长度必须为 BlockSize。
//
// iv 必须为 BlockSize 字节且在每个 (key, message) 对下唯一；CTR 为对称流密码，
// 加解密使用同一函数；在不同消息间重用 (key, iv) 对会破坏机密性。
//
// EncryptCTR encrypts data with AES-CTR (stream mode, no padding).
//
// iv must be exactly BlockSize bytes and must be unique per (key, message);
// CTR is symmetric, so the same function works for both directions, and
// reusing an (key, iv) pair across different messages breaks confidentiality.
func EncryptCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, "ctr")
}

// DecryptCTR 使用 AES-CTR 解密 data（流模式，与加密等价）。
// iv 长度必须为 BlockSize；CTR 是对称算法，解密与加密使用相同函数。
//
// CTR 不提供完整性保护，建议搭配 HMAC 使用或直接选择 AES-GCM。
//
// DecryptCTR decrypts data with AES-CTR (stream mode).
//
// iv must be exactly BlockSize bytes; CTR is symmetric and DecryptCTR is
// functionally identical to EncryptCTR. CTR does not provide integrity
// protection; pair it with an HMAC or prefer AES-GCM.
func DecryptCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, "ctr")
}

// EncryptGCM 使用 AES-GCM 认证加密（AEAD）。返回密文与认证标签。
// nonce 长度必须为 NonceSize（12 字节），tag 长度固定为 TagSize（16 字节）。
//
// nonce 必须在每个 (key, message) 对下唯一——重用 (key, nonce) 对会灾难性地
// 同时破坏机密性与认证性。key 必须为 16（AES-128）或 32（AES-256）字节。
// tag 始终为 TagSize（16）字节。
//
// EncryptGCM authenticates and encrypts plaintext with AES-GCM and returns
// the ciphertext together with the authentication tag.
//
// nonce must be exactly NonceSize (12) bytes and must be unique per
// (key, message) pair — reusing a (key, nonce) pair catastrophically
// breaks both confidentiality and authenticity. key must be 16 (AES-128)
// or 32 (AES-256) bytes. tag is always TagSize (16) bytes.
func EncryptGCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	c, err := aesCipher(key, "gcm")
	if err != nil {
		return nil, nil, err
	}
	ctx, err := core.NewGcmCtx(c, key, nonce, true)
	if err != nil {
		return nil, nil, err
	}
	defer ctx.Close()
	if err := ctx.SetAad(aad); err != nil {
		return nil, nil, err
	}
	ct, err := ctx.EncryptAll(plaintext)
	if err != nil {
		return nil, nil, err
	}
	tag = make([]byte, TagSize)
	if err := ctx.GetTag(tag); err != nil {
		return nil, nil, err
	}
	return ct, tag, nil
}

// DecryptGCM 使用 AES-GCM 认证解密（AEAD）。tag 或 aad 错误时返回错误。
// tag 长度必须为 TagSize；nonce / aad 必须与加密时一致。
//
// tag 或 aad 校验失败或底层 EVP 调用失败时返回错误；调用方须将任意非 nil 错误
// 视为认证失败并丢弃返回的明文，不得据此继续处理。
//
// DecryptGCM verifies and decrypts AES-GCM ciphertext.
//
// tag must be exactly TagSize (16) bytes; nonce and aad must match the
// values used at encryption time. The function returns an error when tag
// or aad verification fails or when the underlying EVP call fails — callers
// must treat the error as an authentication failure and discard the
// returned plaintext rather than act on it.
func DecryptGCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	c, err := aesCipher(key, "gcm")
	if err != nil {
		return nil, err
	}
	if len(tag) != TagSize {
		return nil, fmt.Errorf("aes: invalid tag size %d, want %d", len(tag), TagSize)
	}
	ctx, err := core.NewGcmCtx(c, key, nonce, false)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err := ctx.SetAad(aad); err != nil {
		return nil, err
	}
	if err := ctx.SetTag(tag); err != nil {
		return nil, err
	}
	return ctx.DecryptAll(ciphertext)
}

// aesGCM 是基于 AES-GCM 的 crypto/cipher.AEAD 实现。
//
// aesGCM implements cipher.AEAD on top of AES-GCM via the Tongsuo native
// library.
type aesGCM struct {
	key []byte
}

// NewGCM 返回基于 AES-GCM 的 AEAD 实例（crypto/cipher.AEAD）。
// 密文格式为 ciphertext || tag。
// key 必须为 16（AES-128）或 32（AES-256）字节；其它长度返回错误。
//
// Seal/Open 输出布局为 ciphertext || tag（认证标签追加在密文末尾）；AEAD nonce
// 长度为 NonceSize，认证开销为 TagSize。nonce 不得重用（同 EncryptGCM）。
//
// NewGCM returns a cipher.AEAD implementation backed by AES-GCM.
//
// key must be exactly 16 bytes (AES-128) or 32 bytes (AES-256); any other
// length returns an error. The Seal/Open output layout is ciphertext || tag
// (the tag is appended after ciphertext); the AEAD nonce length is NonceSize
// and the authentication overhead is TagSize. The same nonce-reuse warning
// as EncryptGCM applies.
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("aes: invalid key size %d, want 16 or 32", len(key))
	}
	return &aesGCM{key: key}, nil
}

// NonceSize 返回 Nonce 长度，始终为 NonceSize（12）字节。
//
// NonceSize returns the AEAD nonce size in bytes, always NonceSize (12).
func (g *aesGCM) NonceSize() int { return NonceSize }

// Overhead 返回认证标签长度，始终为 TagSize（16）字节。
//
// Overhead returns the AEAD authentication tag size in bytes, always
// TagSize (16).
func (g *aesGCM) Overhead() int { return TagSize }

// Seal 加密并追加认证标签到 dst（ciphertext || tag）。
// 实现 cipher.AEAD.Seal 语义；nonce 必须每密钥唯一；底层不可能失败。
//
// 底层 EVP 不可达失败时会 panic；对已经通过 EncryptGCM 校验过的输入，此分支
// 不可达。
//
// Seal implements cipher.AEAD.Seal; it encrypts plaintext, authenticates
// additionalData under nonce, and appends ciphertext || tag to dst.
//
// nonce must be unique per key (see EncryptGCM). It panics on an
// unreachable underlying EVP failure; for inputs already validated by
// EncryptGCM this branch is not reachable.
func (g *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ct, tag, err := EncryptGCM(g.key, nonce, plaintext, additionalData)
	if err != nil {
		panic(err)
	}
	dst = append(dst, ct...)
	dst = append(dst, tag...)
	return dst
}

// Open 解密并校验认证标签。
// ciphertext 长度不足 TagSize，或 tag/aad 验证失败时返回错误。
//
// len(ciphertext) < TagSize、tag 校验失败或底层 EVP 错误时返回错误；调用方须将
// 任意非 nil 错误视为认证失败并丢弃返回的部分明文。
//
// Open implements cipher.AEAD.Open; it verifies and decrypts ciphertext
// (whose trailing TagSize bytes are the authentication tag) under nonce
// and additionalData.
//
// It returns an error when len(ciphertext) < TagSize, when tag
// verification fails, or on any underlying EVP error. Callers must treat
// any non-nil error as an authentication failure and discard the partial
// plaintext rather than act on it.
func (g *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("aes: ciphertext too short")
	}
	tag := ciphertext[len(ciphertext)-TagSize:]
	ct := ciphertext[:len(ciphertext)-TagSize]
	pt, err := DecryptGCM(g.key, nonce, ct, tag, additionalData)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}

func cryptAll(key, iv, data []byte, enc bool, mode string) ([]byte, error) {
	c, err := aesCipher(key, mode)
	if err != nil {
		return nil, err
	}
	ctx, err := core.NewCipherCtx(c, key, iv, enc)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if enc {
		return ctx.EncryptAll(data)
	}
	return ctx.DecryptAll(data)
}
