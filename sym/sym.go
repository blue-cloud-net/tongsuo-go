package sym

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// ErrInvalidKeyLength 报告密钥长度不符合算法要求（区分于 ErrUnknownAlgorithm
// 的算法名错误）。
//
// ErrInvalidKeyLength reports that a key's byte length does not match
// the algorithm's requirement (distinct from ErrUnknownAlgorithm).
var ErrInvalidKeyLength = errors.New("sym: invalid key length")

// ErrUnsupported 报告请求的特性在当前构建中不可用（如 GCM 的 SET_IVLEN）。
//
// ErrUnsupported reports a requested feature is unavailable in the
// current build (e.g. GCM's SET_IVLEN).
var ErrUnsupported = errors.New("sym: unsupported")

// Options 是按名 Encrypt/Decrypt 的参数包。
//
// Options carries by-name Encrypt/Decrypt parameters.
type Options struct {
	// Padding 取 "pkcs7"（默认）/ "zero" / "none"。
	//
	// Padding is "pkcs7" (default) / "zero" / "none".
	Padding string
	// AAD 是 AEAD 模式的 AAD（仅 GCM 模式使用）。
	//
	// AAD is the Additional Authenticated Data for AEAD modes.
	AAD []byte
	// Tag 是 AEAD 解密时的输入 tag（仅 GCM 模式使用）。
	//
	// Tag is the AEAD authentication tag for decryption (GCM only).
	Tag []byte
	// Order 保留给将来 SM4-CTR 的字节序场景（暂无消费）。
	//
	// Order is reserved for future SM4-CTR byte-order scenarios.
	Order string
}

// 算法注册项：name（按名分发名） + 期望密钥字节长度（size==0 表示流式/GCM）。
type algo struct {
	name string
	size int // 期望密钥字节长度；ECB/CBC/CTR/OFB/CFB = 16（AES-128/256 用各自 size），GCM 任意
}

// algos 是「算法-模式」名注册表；顺序决定 Names() 返回顺序。
//
// algos is the algorithm-mode registry; the slice order defines the
// stable order returned by Names().
var algos = []algo{
	{"AES-128-CBC", AES128KeySize},
	{"AES-128-CTR", AES128KeySize},
	{"AES-128-ECB", AES128KeySize},
	{"AES-128-GCM", AES128KeySize},
	{"AES-256-CBC", AES256KeySize},
	{"AES-256-CTR", AES256KeySize},
	{"AES-256-ECB", AES256KeySize},
	{"AES-256-GCM", AES256KeySize},
	{"SM4-CBC", SM4KeySize},
	{"SM4-CTR", SM4KeySize},
	{"SM4-ECB", SM4KeySize},
	{"SM4-OFB", SM4KeySize},
	{"SM4-CFB", SM4KeySize},
	{"SM4-GCM", SM4KeySize},
}

// lookup 按算法名查找注册项；名称大小写不敏感。
func lookup(name string) (algo, string, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	for _, a := range algos {
		if a.name == key {
			return a, parseMode(a.name), nil
		}
	}
	return algo{}, "", fmt.Errorf("sym: %q: %w", name, ErrUnknownAlgorithm)
}

// parseMode 从「算法-模式」名拆出模式后缀（"ECB" / "CBC" / "CTR" / ...）。
// 必须从最后一个 "-" 切分，因为「AES-128-GCM」中段 "128" 也含 "-"，取首个会拿到 "128-GCM"。
func parseMode(name string) string {
	if idx := strings.LastIndex(name, "-"); idx >= 0 {
		return name[idx+1:]
	}
	return ""
}

// Names 返回本版已支持的「算法-模式」名（顺序稳定）。
//
// Names returns the algorithm-mode names supported by this version in a
// stable order.
func Names() []string {
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = a.name
	}
	return out
}

// NewCipher 按算法名返回无填充分组密码（cipher.Block）。
// 未知算法名返回 ErrUnknownAlgorithm；密钥长度不符返回 ErrInvalidKeyLength。
//
// NewCipher returns an unpadded cipher.Block by algorithm-mode name.
func NewCipher(name string, key []byte) (cipher.Block, error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if mode == "GCM" {
		return nil, fmt.Errorf("sym: %q: %w: cipher.Block is not applicable to GCM", name, ErrUnsupported)
	}
	if a.size > 0 && len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch {
	case strings.HasPrefix(name, "AES-"):
		return NewAESCipher(key)
	case strings.HasPrefix(name, "SM4-"):
		return NewSM4Cipher(key)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// NewGCM 按算法名返回 GCM AEAD（cipher.AEAD）。
// 未知算法名返回 ErrUnknownAlgorithm；密钥长度不符返回 ErrInvalidKeyLength。
//
// NewGCM returns a GCM cipher.AEAD by algorithm-mode name.
func NewGCM(name string, key []byte) (cipher.AEAD, error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if mode != "GCM" {
		return nil, fmt.Errorf("sym: %q: %w: cipher.AEAD is GCM only", name, ErrUnsupported)
	}
	if a.size > 0 && len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch {
	case strings.HasPrefix(name, "AES-"):
		return NewAESGCM(key)
	case strings.HasPrefix(name, "SM4-"):
		return NewSM4GCM(key)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// Encrypt 按算法名一次性加密。
// 未知算法名返回 ErrUnknownAlgorithm；密钥长度不符返回 ErrInvalidKeyLength。
// GCM 模式请使用 EncryptGCM（需分离 nonce 与 tag）。
//
// Encrypt encrypts in one shot by algorithm-mode name.
func Encrypt(name string, key, iv, data []byte, opts *Options) ([]byte, error) {
	_, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if mode == "GCM" {
		return nil, fmt.Errorf("sym: %q: %w: use EncryptGCM", name, ErrUnsupported)
	}
	pad := "pkcs7"
	if opts != nil && opts.Padding == "zero" {
		pad = "zero"
	} else if opts != nil && opts.Padding == "none" {
		pad = "none"
	}

	switch name {
	case "AES-128-CBC", "AES-256-CBC":
		return EncryptAESCBC(key, iv, data)
	case "AES-128-CTR", "AES-256-CTR":
		return EncryptAESCTR(key, iv, data)
	case "AES-128-ECB", "AES-256-ECB":
		return EncryptAESECB(key, data)
	case "SM4-CBC":
		return encryptSM4WithPad(key, iv, data, true, "cbc", pad)
	case "SM4-CTR":
		return EncryptSM4CTR(key, iv, data)
	case "SM4-ECB":
		return encryptSM4WithPad(key, iv, data, true, "ecb", pad)
	case "SM4-OFB":
		return EncryptSM4OFB(key, iv, data)
	case "SM4-CFB":
		return EncryptSM4CFB(key, iv, data)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// Decrypt 按算法名一次性解密。
func Decrypt(name string, key, iv, data []byte, opts *Options) ([]byte, error) {
	_, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if mode == "GCM" {
		return nil, fmt.Errorf("sym: %q: %w: use DecryptGCM", name, ErrUnsupported)
	}
	pad := "pkcs7"
	if opts != nil && opts.Padding == "zero" {
		pad = "zero"
	} else if opts != nil && opts.Padding == "none" {
		pad = "none"
	}
	switch name {
	case "AES-128-CBC", "AES-256-CBC":
		return DecryptAESCBC(key, iv, data)
	case "AES-128-CTR", "AES-256-CTR":
		return DecryptAESCTR(key, iv, data)
	case "AES-128-ECB", "AES-256-ECB":
		return DecryptAESECB(key, data)
	case "SM4-CBC":
		return encryptSM4WithPad(key, iv, data, false, "cbc", pad)
	case "SM4-CTR":
		return DecryptSM4CTR(key, iv, data)
	case "SM4-ECB":
		return encryptSM4WithPad(key, iv, data, false, "ecb", pad)
	case "SM4-OFB":
		return DecryptSM4OFB(key, iv, data)
	case "SM4-CFB":
		return DecryptSM4CFB(key, iv, data)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// encryptSM4WithPad 按 padding 选择 PKCS#7 / zero / none 的 SM4 ECB/CBC 路径。
//
// encryptSM4WithPad selects PKCS#7 / zero / none padding for SM4 ECB/CBC.
func encryptSM4WithPad(key, iv, data []byte, enc bool, mode, pad string) ([]byte, error) {
	switch pad {
	case "pkcs7":
		return sm4CryptAll(key, iv, data, enc, mode)
	case "zero":
		return sm4CryptZero(key, iv, data, enc, mode)
	case "none":
		return sm4CryptNoPad(key, iv, data, enc, mode)
	}
	return nil, fmt.Errorf("sym: SM4 %s: unsupported padding %q", mode, pad)
}

// sm4CryptNoPad 创建无填充（也不做 zero）的 SM4 上下文。
func sm4CryptNoPad(key, iv, data []byte, enc bool, mode string) ([]byte, error) {
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

// EncryptGCM 按算法名 GCM 加密，返回密文与认证标签。
//
// EncryptGCM encrypts in one shot with GCM by algorithm-mode name.
func EncryptGCM(name string, key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	_, mode, err := lookup(name)
	if err != nil {
		return nil, nil, err
	}
	if mode != "GCM" {
		return nil, nil, fmt.Errorf("sym: %q: %w: EncryptGCM is for GCM only", name, ErrUnsupported)
	}
	switch {
	case strings.HasPrefix(name, "AES-"):
		return EncryptAESGCM(key, nonce, plaintext, aad)
	case strings.HasPrefix(name, "SM4-"):
		return EncryptSM4GCM(key, nonce, plaintext, aad)
	}
	return nil, nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// DecryptGCM 按算法名 GCM 解密。tag 校验失败时返回错误。
func DecryptGCM(name string, key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	_, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if mode != "GCM" {
		return nil, fmt.Errorf("sym: %q: %w: DecryptGCM is for GCM only", name, ErrUnsupported)
	}
	switch {
	case strings.HasPrefix(name, "AES-"):
		return DecryptAESGCM(key, nonce, ciphertext, tag, aad)
	case strings.HasPrefix(name, "SM4-"):
		return DecryptSM4GCM(key, nonce, ciphertext, tag, aad)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}
