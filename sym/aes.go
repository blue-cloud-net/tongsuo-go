package sym

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// aesCipher 选择 Tongsuo 描述符（AES-128 / AES-256 × ECB / CBC / CTR / GCM）。
//
// aesCipher selects the Tongsuo descriptor for the given key size and
// mode ("ecb" / "cbc" / "ctr" / "gcm").
func aesCipher(key []byte, mode string) (*core.Cipher, error) {
	var c *core.Cipher
	switch len(key) {
	case AES128KeySize:
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
	case AES256KeySize:
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
		return nil, fmt.Errorf("sym: invalid AES key size %d, want %d or %d", len(key), AES128KeySize, AES256KeySize)
	}
	if c == nil {
		return nil, fmt.Errorf("sym: AES unsupported mode %q", mode)
	}
	return c, nil
}

// aesCryptAll 通用加解密：选择描述符 → NewCipherCtx → EncryptAll/DecryptAll。
// 失败时返回包装 OpError 的错误。
//
// aesCryptAll drives the core.CipherCtx pipeline.
func aesCryptAll(key, iv, data []byte, enc bool, mode string) ([]byte, error) {
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

// NewAESCipher 返回 AES 分组密码（cipher.Block，无填充）。
// key 必须为 AES128KeySize 或 AES256KeySize。
// 同一 Block 实例可被多个 goroutine 并发复用（底层 EVP_CIPHER_CTX_copy
// 模板副本，与 stdlib cipher.Block 一致）。
//
// NewAESCipher returns an AES cipher.Block (no padding).
// key must be AES128KeySize or AES256KeySize. The same Block is safe
// for concurrent use by multiple goroutines.
func NewAESCipher(key []byte) (cipher.Block, error) {
	c, err := aesCipher(key, "ecb")
	if err != nil {
		return nil, err
	}
	encTpl, err := newAESNoPadCtx(c, key, true)
	if err != nil {
		return nil, err
	}
	decTpl, err := newAESNoPadCtx(c, key, false)
	if err != nil {
		_ = encTpl.Close()
		return nil, err
	}
	return &aesBlock{encTpl: encTpl, decTpl: decTpl}, nil
}

// aesBlock 实现基于铜锁 AES-ECB 的 cipher.Block。
//
// aesBlock implements cipher.Block via Tongsuo AES-ECB (no padding).
type aesBlock struct {
	encTpl *core.CipherCtx // ECB 加密模板（永不在其上调 Update）
	decTpl *core.CipherCtx // ECB 解密模板（永不在其上调 Update）
}

// BlockSize 返回 AES 分组长度（16）。
func (b *aesBlock) BlockSize() int { return BlockSize }

// Encrypt 加密单个分组。
//
// Encrypt encrypts a single 16-byte block from src into dst.
func (b *aesBlock) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sym: AES input not full block")
	}
	if len(dst) < BlockSize {
		panic("sym: AES output too short")
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
//
// Decrypt decrypts a single 16-byte block from src into dst.
func (b *aesBlock) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sym: AES input not full block")
	}
	if len(dst) < BlockSize {
		panic("sym: AES output too short")
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

// newAESNoPadCtx 创建无填充的 AES ECB 上下文（作为模板）。
//
// newAESNoPadCtx creates a no-padding AES ECB context (used as a
// template, not directly for Encrypt/Decrypt).
func newAESNoPadCtx(c *core.Cipher, key []byte, enc bool) (*core.CipherCtx, error) {
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

// aesGCM 实现基于 AES-GCM 的 cipher.AEAD（密文格式 ciphertext || tag）。
//
// aesGCM implements cipher.AEAD on top of AES-GCM via Tongsuo.
type aesGCM struct {
	key []byte
}

// NewAESGCM 返回基于 AES-GCM 的 cipher.AEAD。
// key 必须为 AES128KeySize 或 AES256KeySize；其它长度返回错误。
// Seal/Open 输出格式为 ciphertext || tag（标签追加在密文末尾）。
// nonce 不得重用（同 EncryptGCM 安全说明）。
//
// 安全：AEAD 实例保留对 key 切片的引用（每次 Seal/Open 都复用）；
// **调用方有责任在使用完毕后清零 key 切片**。
//
// NewAESGCM returns a cipher.AEAD implementation backed by AES-GCM.
// key must be AES128KeySize or AES256KeySize; any other length returns
// an error. The Seal/Open output layout is ciphertext || tag.
//
// Security: the AEAD instance retains a reference to the key slice
// (reused on every Seal/Open call); callers MUST zero the key slice
// when done.
func NewAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != AES128KeySize && len(key) != AES256KeySize {
		return nil, fmt.Errorf("sym: invalid AES key size %d, want %d or %d", len(key), AES128KeySize, AES256KeySize)
	}
	return &aesGCM{key: key}, nil
}

// NonceSize 返回 Nonce 长度（12）。
func (g *aesGCM) NonceSize() int { return NonceSize }

// Overhead 返回认证标签长度（16）。
func (g *aesGCM) Overhead() int { return TagSize }

// Seal 加密并追加认证标签到 dst（ciphertext || tag）。
//
// Seal implements cipher.AEAD.Seal.
func (g *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ct, tag, err := EncryptAESGCM(g.key, nonce, plaintext, additionalData)
	if err != nil {
		panic(err)
	}
	dst = append(dst, ct...)
	dst = append(dst, tag...)
	return dst
}

// Open 解密并校验认证标签。
//
// Open implements cipher.AEAD.Open.
func (g *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("sym: AES ciphertext too short")
	}
	tag := ciphertext[len(ciphertext)-TagSize:]
	ct := ciphertext[:len(ciphertext)-TagSize]
	pt, err := DecryptAESGCM(g.key, nonce, ct, tag, additionalData)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}

// EncryptAESECB 使用 AES-ECB 加密（PKCS#7 填充）。
//
// 安全：ECB 无扩散语义，不建议用于多块数据；保留仅为兼容既有格式。
//
// EncryptAESECB encrypts with AES-ECB (PKCS#7 padding).
//
// Security: ECB has no diffusion; not recommended for new protocols.
func EncryptAESECB(key, data []byte) ([]byte, error) {
	return aesCryptAll(key, nil, data, true, "ecb")
}

// DecryptAESECB 使用 AES-ECB 解密（PKCS#7 填充）。
//
// DecryptAESECB decrypts with AES-ECB (PKCS#7 padding).
func DecryptAESECB(key, data []byte) ([]byte, error) {
	return aesCryptAll(key, nil, data, false, "ecb")
}

// EncryptAESCBC 使用 AES-CBC 加密（PKCS#7 填充）。
// iv 必须为 BlockSize。
//
// EncryptAESCBC encrypts with AES-CBC (PKCS#7 padding).
// iv must be BlockSize bytes.
func EncryptAESCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return aesCryptAll(key, iv, data, true, "cbc")
}

// DecryptAESCBC 使用 AES-CBC 解密（PKCS#7 填充）。
//
// DecryptAESCBC decrypts with AES-CBC (PKCS#7 padding).
func DecryptAESCBC(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return aesCryptAll(key, iv, data, false, "cbc")
}

// EncryptAESCTR 使用 AES-CTR 加密（流式模式）。
// iv 必须为 BlockSize；CTR 加解密函数等价（流式 + XOR）。
//
// 安全：CTR 不提供完整性保护，建议搭配 HMAC 使用或直接选择 AES-GCM。
//
// EncryptAESCTR encrypts with AES-CTR (stream mode).
// iv must be BlockSize bytes.
//
// Security: CTR does not provide integrity protection; pair it with
// an HMAC or prefer AES-GCM.
func EncryptAESCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return aesCryptAll(key, iv, data, true, "ctr")
}

// DecryptAESCTR 等价 EncryptAESCTR（流式对称）。
func DecryptAESCTR(key, iv, data []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return aesCryptAll(key, iv, data, false, "ctr")
}

// EncryptAESGCM 使用 AES-GCM 认证加密（AEAD）。返回密文与认证标签。
// nonce 必须为 NonceSize；tag 长度固定为 TagSize。
//
// 安全：nonce 必须在每 (key, message) 对下唯一；重用 (key, nonce) 对会破坏
// 机密性与认证性。
//
// EncryptAESGCM authenticates and encrypts with AES-GCM and returns
// ciphertext and tag.
//
// Security: nonce must be unique per (key, message) pair.
func EncryptAESGCM(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(nonce) != NonceSize {
		return nil, nil, fmt.Errorf("sym: invalid nonce size %d, want %d", len(nonce), NonceSize)
	}
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

// DecryptAESGCM 使用 AES-GCM 认证解密。tag 或 aad 错误时返回错误。
// 调用方须将任意非 nil 错误视为认证失败并丢弃返回的明文。
//
// DecryptAESGCM verifies and decrypts AES-GCM ciphertext.
func DecryptAESGCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("sym: invalid nonce size %d, want %d", len(nonce), NonceSize)
	}
	c, err := aesCipher(key, "gcm")
	if err != nil {
		return nil, err
	}
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
