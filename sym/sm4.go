package sym

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// sm4Cipher 选择 Tongsuo SM4 描述符（ECB / CBC / CTR / OFB / CFB / GCM）。
//
// sm4Cipher selects the Tongsuo SM4 descriptor for the given mode.
func sm4Cipher(mode string) *core.Cipher {
	switch mode {
	case "ecb":
		return core.SM4ECB()
	case "cbc":
		return core.SM4CBC()
	case "ctr":
		return core.SM4CTR()
	case "ofb":
		return core.SM4OFB()
	case "cfb":
		return core.SM4CFB()
	case "gcm":
		return core.SM4GCM()
	}
	return nil
}

// sm4CryptAll 通用加解密。失败时返回包装 OpError 的错误。
func sm4CryptAll(key, iv, data []byte, enc bool, mode string) ([]byte, error) {
	c := sm4Cipher(mode)
	if c == nil {
		return nil, fmt.Errorf("sym: SM4 unsupported mode %q", mode)
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

// NewSM4Cipher 返回 SM4 分组密码（cipher.Block，无填充）。
// key 必须为 SM4KeySize（16 字节）；其它长度返回错误。
// 同一 Block 实例可被多个 goroutine 并发复用。
//
// NewSM4Cipher returns an SM4 cipher.Block (no padding).
// key must be SM4KeySize (16 bytes). The same Block is safe for
// concurrent use by multiple goroutines.
func NewSM4Cipher(key []byte) (cipher.Block, error) {
	if len(key) != SM4KeySize {
		return nil, fmt.Errorf("sym: invalid SM4 key size %d, want %d", len(key), SM4KeySize)
	}
	c := sm4Cipher("ecb")
	encTpl, err := newSM4NoPadCtx(c, key, true)
	if err != nil {
		return nil, err
	}
	decTpl, err := newSM4NoPadCtx(c, key, false)
	if err != nil {
		_ = encTpl.Close()
		return nil, err
	}
	return &sm4Block{encTpl: encTpl, decTpl: decTpl}, nil
}

// sm4Block 实现基于铜锁 SM4-ECB 的 cipher.Block。
type sm4Block struct {
	encTpl *core.CipherCtx
	decTpl *core.CipherCtx
}

// BlockSize 返回 SM4 分组长度（16）。
func (b *sm4Block) BlockSize() int { return BlockSize }

// Encrypt 加密单个分组。
func (b *sm4Block) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sym: SM4 input not full block")
	}
	if len(dst) < BlockSize {
		panic("sym: SM4 output too short")
	}
	ctx, err := b.encTpl.Clone()
	if err != nil {
		panic(err)
	}
	defer ctx.Close()
	out, err := ctx.EncryptAll(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst, out)
}

// Decrypt 解密单个分组。
func (b *sm4Block) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sym: SM4 input not full block")
	}
	if len(dst) < BlockSize {
		panic("sym: SM4 output too short")
	}
	ctx, err := b.decTpl.Clone()
	if err != nil {
		panic(err)
	}
	defer ctx.Close()
	out, err := ctx.DecryptAll(src[:BlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst, out)
}

// newSM4NoPadCtx 创建无填充的 SM4 ECB 上下文（模板）。
func newSM4NoPadCtx(c *core.Cipher, key []byte, enc bool) (*core.CipherCtx, error) {
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

// sm4GCM 实现基于 SM4-GCM 的 cipher.AEAD。
type sm4GCM struct {
	key []byte
}

// NewSM4GCM 返回基于 SM4-GCM 的 cipher.AEAD。
// key 必须为 SM4KeySize（16 字节）；其它长度返回错误。
// Seal/Open 输出格式为 ciphertext || tag。
//
// 安全：AEAD 实例保留对 key 切片的引用；调用方负责使用完清零 key。
//
// NewSM4GCM returns a cipher.AEAD backed by SM4-GCM.
// key must be SM4KeySize (16 bytes).
//
// Security: the AEAD instance retains the key reference; callers
// MUST zero the key when done.
func NewSM4GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != SM4KeySize {
		return nil, fmt.Errorf("sym: invalid SM4 key size %d, want %d", len(key), SM4KeySize)
	}
	return &sm4GCM{key: key}, nil
}

// NonceSize 返回 SM4-GCM 推荐 nonce 长度（12）。
func (g *sm4GCM) NonceSize() int { return NonceSize }

// Overhead 返回 SM4-GCM 标签长度（16）。
func (g *sm4GCM) Overhead() int { return TagSize }

// Seal 实现 cipher.AEAD.Seal。
func (g *sm4GCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ct, tag, err := EncryptSM4GCM(g.key, nonce, plaintext, additionalData)
	if err != nil {
		panic(err)
	}
	dst = append(dst, ct...)
	dst = append(dst, tag...)
	return dst
}

// Open 实现 cipher.AEAD.Open。
func (g *sm4GCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("sym: SM4 ciphertext too short")
	}
	tag := ciphertext[len(ciphertext)-TagSize:]
	ct := ciphertext[:len(ciphertext)-TagSize]
	pt, err := DecryptSM4GCM(g.key, nonce, ct, tag, additionalData)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}

// EncryptSM4ECB 使用 SM4-ECB 加密（PKCS#7 填充）。
func EncryptSM4ECB(key, data []byte) ([]byte, error) {
	return sm4CryptAll(key, nil, data, true, "ecb")
}

// DecryptSM4ECB 使用 SM4-ECB 解密（PKCS#7 填充）。
func DecryptSM4ECB(key, data []byte) ([]byte, error) {
	return sm4CryptAll(key, nil, data, false, "ecb")
}

// EncryptSM4ECBZero 使用 SM4-ECB 加密（零填充）。
//
// EncryptSM4ECBZero uses SM4-ECB with zero padding.
func EncryptSM4ECBZero(key, data []byte) ([]byte, error) {
	return sm4CryptZero(key, nil, data, true, "ecb")
}

// DecryptSM4ECBZero 使用 SM4-ECB 解密（零填充）。
func DecryptSM4ECBZero(key, data []byte) ([]byte, error) {
	return sm4CryptZero(key, nil, data, false, "ecb")
}

// EncryptSM4CBC 使用 SM4-CBC 加密（PKCS#7 填充）。
func EncryptSM4CBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, true, "cbc")
}

// DecryptSM4CBC 使用 SM4-CBC 解密（PKCS#7 填充）。
func DecryptSM4CBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, false, "cbc")
}

// EncryptSM4CBCZero 使用 SM4-CBC 加密（零填充）。
func EncryptSM4CBCZero(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptZero(key, iv, data, true, "cbc")
}

// DecryptSM4CBCZero 使用 SM4-CBC 解密（零填充）。
func DecryptSM4CBCZero(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptZero(key, iv, data, false, "cbc")
}

// EncryptSM4CTR 使用 SM4-CTR 加密（流式）。
func EncryptSM4CTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, true, "ctr")
}

// DecryptSM4CTR 等价 EncryptSM4CTR（流式对称）。
func DecryptSM4CTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, false, "ctr")
}

// EncryptSM4OFB 使用 SM4-OFB 加密（流式）。
func EncryptSM4OFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, true, "ofb")
}

// DecryptSM4OFB 使用 SM4-OFB 解密（流式）。
func DecryptSM4OFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, false, "ofb")
}

// EncryptSM4CFB 使用 SM4-CFB 加密（流式）。
func EncryptSM4CFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, true, "cfb")
}

// DecryptSM4CFB 使用 SM4-CFB 解密（流式）。
func DecryptSM4CFB(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return sm4CryptAll(key, iv, data, false, "cfb")
}

// EncryptSM4GCM 使用 SM4-GCM 认证加密。
//
// 安全：nonce 必须在每 (key, message) 对下唯一。
func EncryptSM4GCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(nonce) != NonceSize {
		return nil, nil, fmt.Errorf("sym: invalid nonce size %d, want %d", len(nonce), NonceSize)
	}
	c := sm4Cipher("gcm")
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

// DecryptSM4GCM 使用 SM4-GCM 认证解密。tag 或 aad 错误时返回错误。
func DecryptSM4GCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("sym: invalid nonce size %d, want %d", len(nonce), NonceSize)
	}
	c := sm4Cipher("gcm")
	if len(tag) != TagSize {
		return nil, fmt.Errorf("sym: invalid tag size %d, want %d", len(tag), TagSize)
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

// sm4CryptZero 创建无填充的 SM4 上下文后调用底层 CryptAll。
func sm4CryptZero(key, iv, data []byte, enc bool, mode string) ([]byte, error) {
	c := sm4Cipher(mode)
	if c == nil {
		return nil, fmt.Errorf("sym: SM4 unsupported mode %q", mode)
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
