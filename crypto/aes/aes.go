// Package aes 基于铜锁原生实现实现 AES 分组加密（128 / 256 位）。
//
// 提供标准库 cipher.Block 接口（NewCipher）、一次性便捷函数
// （EncryptECB / EncryptCBC / EncryptCTR / EncryptGCM 等）以及 AEAD 接口（NewGCM）。
package aes

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// BlockSize 为 AES 分组长度（字节）。
const BlockSize = 16

// gcm 相关常量。
const (
	// NonceSize 为 AES-GCM 推荐的 Nonce 长度（96 位）。
	NonceSize = 12
	// TagSize 为 AES-GCM 认证标签长度（128 位）。
	TagSize = 16
)

// aesCipher 根据密钥长度选择对应 AES 算法描述符。
// mode 取 "ecb" / "cbc" / "ctr" / "gcm"。
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
type aesBlock struct {
	enc *core.CipherCtx // ECB、无填充
	dec *core.CipherCtx
}

// NewCipher 返回使用给定密钥的 AES 分组加密器（cipher.Block）。
// key 必须为 16（AES-128）或 32（AES-256）字节。
func NewCipher(key []byte) (cipher.Block, error) {
	c, err := aesCipher(key, "ecb")
	if err != nil {
		return nil, err
	}
	enc, err := newNoPadCtx(key, c, true)
	if err != nil {
		return nil, err
	}
	dec, err := newNoPadCtx(key, c, false)
	if err != nil {
		_ = enc.Close()
		return nil, err
	}
	return &aesBlock{enc: enc, dec: dec}, nil
}

// Encrypt 加密一个分组（16 字节）。
func (b *aesBlock) Encrypt(dst, src []byte) {
	if len(dst) < BlockSize || len(src) < BlockSize {
		panic("aes: invalid block size")
	}
	out, err := b.enc.Update(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst[:BlockSize], out)
}

// Decrypt 解密一个分组（16 字节）。
func (b *aesBlock) Decrypt(dst, src []byte) {
	if len(dst) < BlockSize || len(src) < BlockSize {
		panic("aes: invalid block size")
	}
	out, err := b.dec.Update(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst[:BlockSize], out)
}

// BlockSize 返回分组长度。
func (b *aesBlock) BlockSize() int { return BlockSize }

// EncryptECB 使用 AES-ECB 加密 data（PKCS7 填充）。
func EncryptECB(key, data []byte) ([]byte, error) {
	return cryptAll(key, nil, data, true, "ecb")
}

// DecryptECB 使用 AES-ECB 解密 data（PKCS7 填充）。
func DecryptECB(key, data []byte) ([]byte, error) {
	return cryptAll(key, nil, data, false, "ecb")
}

// EncryptCBC 使用 AES-CBC 加密 data（PKCS7 填充）。iv 长度必须为 BlockSize。
func EncryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, "cbc")
}

// DecryptCBC 使用 AES-CBC 解密 data（PKCS7 填充）。iv 须与加密时一致。
func DecryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, "cbc")
}

// EncryptCTR 使用 AES-CTR 加密 data（流模式，无填充）。iv 长度必须为 BlockSize。
func EncryptCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, "ctr")
}

// DecryptCTR 使用 AES-CTR 解密 data（流模式，与加密等价）。
func DecryptCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("aes: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, "ctr")
}

// EncryptGCM 使用 AES-GCM 认证加密（AEAD）。返回密文与认证标签。
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
type aesGCM struct {
	key []byte
}

// NewGCM 返回基于 AES-GCM 的 AEAD 实例（crypto/cipher.AEAD）。
// 密文格式为 ciphertext || tag。
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("aes: invalid key size %d, want 16 or 32", len(key))
	}
	return &aesGCM{key: key}, nil
}

// NonceSize 返回 Nonce 长度。
func (g *aesGCM) NonceSize() int { return NonceSize }

// Overhead 返回认证标签长度。
func (g *aesGCM) Overhead() int { return TagSize }

// Seal 加密并追加认证标签到 dst（ciphertext || tag）。
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
