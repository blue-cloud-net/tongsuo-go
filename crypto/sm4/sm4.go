// Package sm4 基于铜锁原生实现实现 GB/T 32907-2016 SM4 分组加密算法。
//
// 提供标准库 cipher.Block 接口（NewCipher）与一次性便捷函数
// （EncryptECB / DecryptECB / EncryptCBC / DecryptCBC，默认 PKCS7 填充）。
package sm4

import (
	"bytes"
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

const (
	// BlockSize 为 SM4 分组长度（字节）。
	BlockSize = 16
	// KeySize 为 SM4 密钥长度（字节）。
	KeySize = 16
	// NonceSize 为 SM4-GCM 推荐的 Nonce 长度（96 位）。
	NonceSize = 12
	// TagSize 为 SM4-GCM 认证标签长度（128 位）。
	TagSize = 16
)

// sm4Block 是基于铜锁 EVP 的 SM4 单块加密封装，实现 cipher.Block。
type sm4Block struct {
	enc *core.CipherCtx // ECB、无填充
	dec *core.CipherCtx
}

// NewCipher 返回使用给定密钥的 SM4 分组加密器（cipher.Block）。
// 底层基于 SM4-ECB 无填充模式；单块 Encrypt/Decrypt 独立处理。
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("sm4: invalid key size %d, want %d", len(key), KeySize)
	}
	enc, err := newNoPadCtx(key, true)
	if err != nil {
		return nil, err
	}
	dec, err := newNoPadCtx(key, false)
	if err != nil {
		_ = enc.Close()
		return nil, err
	}
	return &sm4Block{enc: enc, dec: dec}, nil
}

func newNoPadCtx(key []byte, enc bool) (*core.CipherCtx, error) {
	ctx, err := core.NewCipherCtx(core.SM4ECB(), key, nil, enc)
	if err != nil {
		return nil, err
	}
	if err := ctx.SetPadding(false); err != nil {
		_ = ctx.Close()
		return nil, err
	}
	return ctx, nil
}

// Encrypt 加密一个分组（16 字节）。
func (b *sm4Block) Encrypt(dst, src []byte) {
	if len(dst) < BlockSize || len(src) < BlockSize {
		panic("sm4: invalid block size")
	}
	out, err := b.enc.Update(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst[:BlockSize], out)
}

// Decrypt 解密一个分组（16 字节）。
func (b *sm4Block) Decrypt(dst, src []byte) {
	if len(dst) < BlockSize || len(src) < BlockSize {
		panic("sm4: invalid block size")
	}
	out, err := b.dec.Update(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst[:BlockSize], out)
}

// BlockSize 返回分组长度。
func (b *sm4Block) BlockSize() int { return BlockSize }

// EncryptECB 使用 SM4-ECB 加密 data（PKCS7 填充）。
func EncryptECB(key, data []byte) ([]byte, error) {
	return cryptAll(key, nil, data, true, core.SM4ECB())
}

// DecryptECB 使用 SM4-ECB 解密 data（PKCS7 填充）。
func DecryptECB(key, data []byte) ([]byte, error) {
	return cryptAll(key, nil, data, false, core.SM4ECB())
}

// EncryptCBC 使用 SM4-CBC 加密 data（PKCS7 填充）。
// iv 长度必须为 BlockSize。
func EncryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, core.SM4CBC())
}

// DecryptCBC 使用 SM4-CBC 解密 data（PKCS7 填充）。
// iv 长度必须为 BlockSize，且与加密时一致。
func DecryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, core.SM4CBC())
}

// EncryptECBZero 使用 SM4-ECB 加密 data（Zero 填充，补零到 BlockSize 倍数）。
// 注意：Zero 填充不记录原始长度，解密时去除尾部 0x00；仅当明文不以 0x00 结尾时可靠。
func EncryptECBZero(key, data []byte) ([]byte, error) {
	return cryptAllNoPad(key, nil, zeroPad(data), true, core.SM4ECB())
}

// DecryptECBZero 使用 SM4-ECB 解密 data（Zero 填充）。
func DecryptECBZero(key, data []byte) ([]byte, error) {
	out, err := cryptAllNoPad(key, nil, data, false, core.SM4ECB())
	if err != nil {
		return nil, err
	}
	return zeroUnpad(out), nil
}

// EncryptCBCZero 使用 SM4-CBC 加密 data（Zero 填充）。
// iv 长度必须为 BlockSize。
func EncryptCBCZero(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAllNoPad(key, iv, zeroPad(data), true, core.SM4CBC())
}

// DecryptCBCZero 使用 SM4-CBC 解密 data（Zero 填充）。
// iv 必须与加密时一致。
func DecryptCBCZero(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	out, err := cryptAllNoPad(key, iv, data, false, core.SM4CBC())
	if err != nil {
		return nil, err
	}
	return zeroUnpad(out), nil
}

// zeroPad 将 data 补零到 BlockSize 的整数倍（至少补 1 字节）。
func zeroPad(data []byte) []byte {
	padding := BlockSize - len(data)%BlockSize
	out := make([]byte, 0, len(data)+padding)
	out = append(out, data...)
	out = append(out, bytes.Repeat([]byte{0}, padding)...)
	return out
}

// zeroUnpad 去除 data 尾部的 0x00 填充。
func zeroUnpad(data []byte) []byte {
	return bytes.TrimRight(data, "\x00")
}

// cryptAllNoPad 与 cryptAll 相同，但关闭填充（配合 Zero 填充在 Go 层处理）。
func cryptAllNoPad(key, iv, data []byte, enc bool, c *core.Cipher) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("sm4: invalid key size %d, want %d", len(key), KeySize)
	}
	ctx, err := core.NewCipherCtx(c, key, iv, enc)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err := ctx.SetPadding(false); err != nil {
		return nil, err
	}
	if enc {
		return ctx.EncryptAll(data)
	}
	return ctx.DecryptAll(data)
}

func cryptAll(key, iv, data []byte, enc bool, c *core.Cipher) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("sm4: invalid key size %d, want %d", len(key), KeySize)
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

// EncryptCTR 使用 SM4-CTR 加密 data（流模式，无填充）。
// iv 长度必须为 BlockSize。
func EncryptCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, core.SM4CTR())
}

// DecryptCTR 使用 SM4-CTR 解密 data（流模式，与加密等价）。
// iv 必须与加密时一致。
func DecryptCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, core.SM4CTR())
}

// EncryptOFB 使用 SM4-OFB 加密 data（流模式，无填充）。
func EncryptOFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, core.SM4OFB())
}

// DecryptOFB 使用 SM4-OFB 解密 data（流模式，与加密等价）。
func DecryptOFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, core.SM4OFB())
}

// EncryptCFB 使用 SM4-CFB 加密 data（流模式，无填充）。
func EncryptCFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, true, core.SM4CFB())
}

// DecryptCFB 使用 SM4-CFB 解密 data（流模式，与加密等价）。
func DecryptCFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptAll(key, iv, data, false, core.SM4CFB())
}

// EncryptGCM 使用 SM4-GCM 认证加密（AEAD）。
// 返回密文与认证标签；解密时须提供相同 nonce、aad 与 tag。
// nonce 推荐 NonceSize（12）字节；aad 可为空，仅参与认证。
func EncryptGCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("sm4: invalid key size %d, want %d", len(key), KeySize)
	}
	ctx, err := core.NewGcmCtx(core.SM4GCM(), key, nonce, true)
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

// DecryptGCM 使用 SM4-GCM 认证解密（AEAD）。
// 提供错误 tag 或与加密不一致的 aad 时返回错误。
func DecryptGCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("sm4: invalid key size %d, want %d", len(key), KeySize)
	}
	if len(tag) != TagSize {
		return nil, fmt.Errorf("sm4: invalid tag size %d, want %d", len(tag), TagSize)
	}
	ctx, err := core.NewGcmCtx(core.SM4GCM(), key, nonce, false)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err := ctx.SetAad(aad); err != nil {
		return nil, err
	}
	// 认证标签必须在 Final 之前设置。
	if err := ctx.SetTag(tag); err != nil {
		return nil, err
	}
	return ctx.DecryptAll(ciphertext)
}

// gcm 是基于 SM4-GCM 的 crypto/cipher.AEAD 实现。
type gcm struct {
	key []byte
}

// NewGCM 返回基于 SM4-GCM 的 AEAD 实例（crypto/cipher.AEAD）。
// 密文格式为 ciphertext || tag（与 Go 标准库 AEAD 一致）。
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("sm4: invalid key size %d, want %d", len(key), KeySize)
	}
	return &gcm{key: key}, nil
}

// NonceSize 返回 Nonce 长度。
func (g *gcm) NonceSize() int { return NonceSize }

// Overhead 返回认证标签长度。
func (g *gcm) Overhead() int { return TagSize }

// Seal 加密并追加认证标签到 dst（ciphertext || tag）。
func (g *gcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ct, tag, err := EncryptGCM(g.key, nonce, plaintext, additionalData)
	if err != nil {
		panic(err)
	}
	dst = append(dst, ct...)
	dst = append(dst, tag...)
	return dst
}

// Open 解密并校验认证标签。
func (g *gcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("sm4: ciphertext too short")
	}
	tag := ciphertext[len(ciphertext)-TagSize:]
	ct := ciphertext[:len(ciphertext)-TagSize]
	pt, err := DecryptGCM(g.key, nonce, ct, tag, additionalData)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}
