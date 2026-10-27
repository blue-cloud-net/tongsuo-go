package sym

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// ChaCha20 与 ChaCha20-Poly1305 的实现。
//
// ChaCha20 是流密码：32 字节密钥、16 字节 IV（4 字节计数器 + 12 字节
// nonce），加解密对称。ChaCha20-Poly1305 是 AEAD：32 字节密钥、12 字节
// nonce、16 字节标签，密文布局为 ciphertext || tag。

// EncryptChaCha20 使用 ChaCha20 流密码加密。
// key 必须为 ChaCha20KeySize（32 字节）；iv 必须为 ChaCha20IVSize（16 字节）。
//
// 安全：IV/计数器必须在每个 (key, message) 对中唯一；复用会破坏机密性。
// ChaCha20 不提供完整性保护，需要时请选 ChaCha20-Poly1305。
//
// EncryptChaCha20 encrypts with the ChaCha20 stream cipher.
// key must be ChaCha20KeySize (32 bytes); iv must be ChaCha20IVSize
// (16 bytes).
//
// Security: the IV/counter MUST be unique per (key, message) pair; reuse
// breaks confidentiality. ChaCha20 provides no integrity protection; use
// ChaCha20-Poly1305 when integrity is required.
func EncryptChaCha20(key, iv, data []byte) ([]byte, error) {
	return chacha20XOR(key, iv, data)
}

// DecryptChaCha20 等于 EncryptChaCha20（流式对称）。
//
// DecryptChaCha20 is identical to EncryptChaCha20 (a symmetric stream
// cipher).
func DecryptChaCha20(key, iv, data []byte) ([]byte, error) {
	return chacha20XOR(key, iv, data)
}

// chacha20XOR 是 ChaCha20 的实现主体。
//
// chacha20XOR is the shared implementation of ChaCha20.
func chacha20XOR(key, iv, data []byte) ([]byte, error) {
	if len(key) != ChaCha20KeySize {
		return nil, fmt.Errorf("sym: invalid ChaCha20 key size %d, want %d", len(key), ChaCha20KeySize)
	}
	if len(iv) != ChaCha20IVSize {
		return nil, fmt.Errorf("sym: invalid ChaCha20 iv size %d, want %d", len(iv), ChaCha20IVSize)
	}
	c := core.ChaCha20()
	if c == nil {
		return nil, fmt.Errorf("sym: ChaCha20 is unavailable in this build")
	}
	ctx, err := core.NewCipherCtx(c, key, iv, true)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err := ctx.SetPadding(false); err != nil {
		return nil, err
	}
	return ctx.EncryptAll(data)
}

// chacha20Poly1305 实现基于 ChaCha20-Poly1305 的 cipher.AEAD。
//
// chacha20Poly1305 implements cipher.AEAD on top of ChaCha20-Poly1305.
type chacha20Poly1305 struct {
	key []byte
}

// NewChaCha20Poly1305 返回基于 ChaCha20-Poly1305 的 cipher.AEAD。
// key 必须为 ChaCha20KeySize（32 字节）；nonce 固定 12 字节；
// Seal/Open 输出格式为 ciphertext || tag。
//
// 安全：AEAD 实例保留对 key 切片的引用（每次 Seal/Open 都复用）；
// **调用方有责任在使用完毕后清零 key 切片**。nonce 不得重用。
//
// NewChaCha20Poly1305 returns a cipher.AEAD implementation backed by
// ChaCha20-Poly1305. key must be ChaCha20KeySize (32 bytes); the nonce is
// exactly 12 bytes; the Seal/Open layout is ciphertext || tag.
//
// Security: the AEAD instance retains a reference to the key slice
// (reused on every Seal/Open call); callers MUST zero the key slice when
// done. The nonce MUST NOT be reused.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != ChaCha20KeySize {
		return nil, fmt.Errorf("sym: invalid ChaCha20 key size %d, want %d", len(key), ChaCha20KeySize)
	}
	return &chacha20Poly1305{key: key}, nil
}

// NonceSize 返回 Nonce 长度（12）。
//
// NonceSize returns the nonce length (12).
func (g *chacha20Poly1305) NonceSize() int { return NonceSize }

// Overhead 返回认证标签长度（16）。
//
// Overhead returns the authentication tag length (16).
func (g *chacha20Poly1305) Overhead() int { return TagSize }

// Seal 加密并追加认证标签到 dst（ciphertext || tag）。
//
// Seal implements cipher.AEAD.Seal.
func (g *chacha20Poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ct, tag, err := EncryptChaCha20Poly1305(g.key, nonce, plaintext, additionalData)
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
func (g *chacha20Poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("sym: ChaCha20-Poly1305 ciphertext too short")
	}
	tag := ciphertext[len(ciphertext)-TagSize:]
	ct := ciphertext[:len(ciphertext)-TagSize]
	pt, err := DecryptChaCha20Poly1305(g.key, nonce, ct, tag, additionalData)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}

// EncryptChaCha20Poly1305 使用 ChaCha20-Poly1305 认证加密，返回密文与标签。
// key 必须为 ChaCha20KeySize；nonce 必须为 NonceSize（12）；aad 可为空。
//
// 安全：同一 (key, nonce) 对严禁重复使用。
//
// EncryptChaCha20Poly1305 encrypts and authenticates with
// ChaCha20-Poly1305 and returns the ciphertext and tag. key must be
// ChaCha20KeySize; the nonce must be NonceSize (12); aad may be empty.
//
// Security: a (key, nonce) pair MUST NOT be reused.
func EncryptChaCha20Poly1305(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(key) != ChaCha20KeySize {
		return nil, nil, fmt.Errorf("sym: invalid ChaCha20 key size %d, want %d", len(key), ChaCha20KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, nil, fmt.Errorf("sym: invalid nonce size %d, want %d", len(nonce), NonceSize)
	}
	c := core.ChaCha20Poly1305()
	if c == nil {
		return nil, nil, fmt.Errorf("sym: ChaCha20-Poly1305 is unavailable in this build")
	}
	ctx, err := core.NewGcmCtx(c, key, nonce, true)
	if err != nil {
		return nil, nil, err
	}
	defer ctx.Close()
	if len(aad) > 0 {
		if err := ctx.SetAad(aad); err != nil {
			return nil, nil, err
		}
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

// DecryptChaCha20Poly1305 使用 ChaCha20-Poly1305 认证解密。
// tag 或 aad 错误时返回错误；调用方须将任意非 nil 错误视为认证失败并
// 丢弃返回的明文。
//
// DecryptChaCha20Poly1305 verifies and decrypts ChaCha20-Poly1305
// ciphertext. A tag or AAD mismatch yields an error; callers MUST treat
// any non-nil error as an authentication failure and discard the
// returned plaintext.
func DecryptChaCha20Poly1305(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(key) != ChaCha20KeySize {
		return nil, fmt.Errorf("sym: invalid ChaCha20 key size %d, want %d", len(key), ChaCha20KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("sym: invalid nonce size %d, want %d", len(nonce), NonceSize)
	}
	if len(tag) != TagSize {
		return nil, fmt.Errorf("sym: invalid tag size %d, want %d", len(tag), TagSize)
	}
	c := core.ChaCha20Poly1305()
	if c == nil {
		return nil, fmt.Errorf("sym: ChaCha20-Poly1305 is unavailable in this build")
	}
	ctx, err := core.NewGcmCtx(c, key, nonce, false)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err := ctx.SetTag(tag); err != nil {
		return nil, err
	}
	if len(aad) > 0 {
		if err := ctx.SetAad(aad); err != nil {
			return nil, err
		}
	}
	return ctx.DecryptAll(ciphertext)
}
