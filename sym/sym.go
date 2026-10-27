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
	size int // 期望密钥字节长度；ECB/CBC/CTR/OFB/CFB = 16（AES-128/256 用各自 size），GCM/XTS 等见各自条目
	mode string
}

// algos 是「算法-模式」名注册表；顺序决定 Names() 返回顺序。
//
// algos is the algorithm-mode registry; the slice order defines the
// stable order returned by Names().
var algos = []algo{
	{"AES-128-CBC", AES128KeySize, "CBC"},
	{"AES-128-CTR", AES128KeySize, "CTR"},
	{"AES-128-ECB", AES128KeySize, "ECB"},
	{"AES-128-GCM", AES128KeySize, "GCM"},
	{"AES-192-CBC", AES192KeySize, "CBC"},
	{"AES-192-CTR", AES192KeySize, "CTR"},
	{"AES-192-ECB", AES192KeySize, "ECB"},
	{"AES-192-GCM", AES192KeySize, "GCM"},
	{"AES-256-CBC", AES256KeySize, "CBC"},
	{"AES-256-CTR", AES256KeySize, "CTR"},
	{"AES-256-ECB", AES256KeySize, "ECB"},
	{"AES-256-GCM", AES256KeySize, "GCM"},
	{"SM4-CBC", SM4KeySize, "CBC"},
	{"SM4-CCM", SM4KeySize, "CCM"},
	{"SM4-CFB", SM4KeySize, "CFB"},
	{"SM4-CTR", SM4KeySize, "CTR"},
	{"SM4-ECB", SM4KeySize, "ECB"},
	{"SM4-GCM", SM4KeySize, "GCM"},
	{"SM4-OFB", SM4KeySize, "OFB"},
	{"SM4-XTS", SM4XTSKeySize, "XTS"},
	{"ChaCha20", ChaCha20KeySize, "STREAM"},
	{"ChaCha20-Poly1305", ChaCha20KeySize, "POLY1305"},
}

// lookup 按算法名查找注册项；名称大小写不敏感。
func lookup(name string) (algo, string, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	for _, a := range algos {
		if strings.ToUpper(a.name) == key {
			return a, a.mode, nil
		}
	}
	return algo{}, "", fmt.Errorf("sym: %q: %w", name, ErrUnknownAlgorithm)
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
// AEAD 模式（GCM / CCM / ChaCha20-Poly1305）、流模式（ChaCha20）与 XTS
// 不提供 cipher.Block 形态，返回 ErrUnsupported（请用 NewAEAD / EncryptAEAD
// 或对应的类型化入口）。
//
// NewCipher returns an unpadded cipher.Block by algorithm-mode name.
func NewCipher(name string, key []byte) (cipher.Block, error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "GCM", "CCM", "POLY1305":
		return nil, fmt.Errorf("sym: %q: %w: cipher.Block is not applicable to AEAD modes", name, ErrUnsupported)
	case "XTS", "STREAM":
		return nil, fmt.Errorf("sym: %q: %w: cipher.Block is not applicable to mode %s", name, ErrUnsupported, mode)
	}
	if a.size > 0 && len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch {
	case strings.HasPrefix(strings.ToUpper(name), "AES-"):
		return NewAESCipher(key)
	case strings.HasPrefix(strings.ToUpper(name), "SM4-"):
		return NewSM4Cipher(key)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// NewGCM 按算法名返回 GCM AEAD（cipher.AEAD）。
// 未知算法名返回 ErrUnknownAlgorithm；密钥长度不符返回 ErrInvalidKeyLength。
// 非 GCM 模式返回 ErrUnsupported（其它 AEAD 用 NewAEAD）。
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
	case strings.HasPrefix(strings.ToUpper(name), "AES-"):
		return NewAESGCM(key)
	case strings.HasPrefix(strings.ToUpper(name), "SM4-"):
		return NewSM4GCM(key)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// NewAEAD 按算法名返回 AEAD 实现（cipher.AEAD）。
// 支持 GCM（AES-128/192/256、SM4）、CCM（SM4）与 ChaCha20-Poly1305。
// 未知算法名返回 ErrUnknownAlgorithm；非 AEAD 模式返回 ErrUnsupported。
//
// NewAEAD returns a cipher.AEAD by algorithm-mode name. It supports GCM
// (AES-128/192/256, SM4), CCM (SM4) and ChaCha20-Poly1305. Unknown names
// return ErrUnknownAlgorithm; non-AEAD modes return ErrUnsupported.
func NewAEAD(name string, key []byte) (cipher.AEAD, error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if a.size > 0 && len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch mode {
	case "GCM":
		return NewGCM(name, key)
	case "CCM":
		return NewSM4CCM(key)
	case "POLY1305":
		return NewChaCha20Poly1305(key)
	}
	return nil, fmt.Errorf("sym: %q: %w: not an AEAD mode", name, ErrUnsupported)
}

// Encrypt 按算法名一次性加密。
// 未知算法名返回 ErrUnknownAlgorithm；密钥长度不符返回 ErrInvalidKeyLength。
// AEAD 模式请用 EncryptAEAD / EncryptGCM（需分离 nonce 与 tag）；
// 流模式 ChaCha20 用 EncryptChaCha20，SM4-XTS 用 EncryptSM4XTS。
//
// Encrypt encrypts in one shot by algorithm-mode name.
func Encrypt(name string, key, iv, data []byte, opts *Options) ([]byte, error) {
	_, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "GCM", "CCM", "POLY1305":
		return nil, fmt.Errorf("sym: %q: %w: use EncryptAEAD", name, ErrUnsupported)
	}
	pad := "pkcs7"
	if opts != nil && opts.Padding == "zero" {
		pad = "zero"
	} else if opts != nil && opts.Padding == "none" {
		pad = "none"
	}

	switch strings.ToUpper(name) {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return EncryptAESCBC(key, iv, data)
	case "AES-128-CTR", "AES-192-CTR", "AES-256-CTR":
		return EncryptAESCTR(key, iv, data)
	case "AES-128-ECB", "AES-192-ECB", "AES-256-ECB":
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
	case "SM4-XTS":
		return EncryptSM4XTS(key, iv, data)
	case "CHACHA20":
		return EncryptChaCha20(key, iv, data)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// Decrypt 按算法名一次性解密。
// 语义与 Encrypt 对称：AEAD 模式请用 DecryptAEAD / DecryptGCM。
//
// Decrypt decrypts in one shot by algorithm-mode name.
func Decrypt(name string, key, iv, data []byte, opts *Options) ([]byte, error) {
	_, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "GCM", "CCM", "POLY1305":
		return nil, fmt.Errorf("sym: %q: %w: use DecryptAEAD", name, ErrUnsupported)
	}
	pad := "pkcs7"
	if opts != nil && opts.Padding == "zero" {
		pad = "zero"
	} else if opts != nil && opts.Padding == "none" {
		pad = "none"
	}
	switch strings.ToUpper(name) {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return DecryptAESCBC(key, iv, data)
	case "AES-128-CTR", "AES-192-CTR", "AES-256-CTR":
		return DecryptAESCTR(key, iv, data)
	case "AES-128-ECB", "AES-192-ECB", "AES-256-ECB":
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
	case "SM4-XTS":
		return DecryptSM4XTS(key, iv, data)
	case "CHACHA20":
		return DecryptChaCha20(key, iv, data)
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
	case strings.HasPrefix(strings.ToUpper(name), "AES-"):
		return EncryptAESGCM(key, nonce, plaintext, aad)
	case strings.HasPrefix(strings.ToUpper(name), "SM4-"):
		return EncryptSM4GCM(key, nonce, plaintext, aad)
	}
	return nil, nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// EncryptAEAD 按算法名 AEAD 加密，返回密文与认证标签。
// 支持 GCM（AES-128/192/256、SM4）、CCM（SM4）与 ChaCha20-Poly1305。
// nonce 长度：GCM 为 12（也允许其它非空长度），CCM 为 7..13，
// ChaCha20-Poly1305 固定 12；tag 长度固定为 TagSize（16）。
// 未知算法名返回 ErrUnknownAlgorithm；非 AEAD 模式返回 ErrUnsupported。
//
// 安全：nonce 必须在每个 (key, message) 对中唯一；复用会同时破坏
// 机密性与真实性。
//
// EncryptAEAD encrypts in one shot with the named AEAD algorithm and
// returns ciphertext and tag. It supports GCM (AES-128/192/256, SM4),
// CCM (SM4) and ChaCha20-Poly1305. Nonce length: 12 for GCM (other
// non-empty lengths are tolerated), 7 to 13 for CCM, and exactly 12 for
// ChaCha20-Poly1305; the tag is always TagSize (16) bytes. Unknown names
// return ErrUnknownAlgorithm; non-AEAD modes return ErrUnsupported.
//
// Security: the nonce MUST be unique per (key, message) pair; reuse
// breaks both confidentiality and authenticity.
func EncryptAEAD(name string, key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, nil, err
	}
	if a.size > 0 && len(key) != a.size {
		return nil, nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch mode {
	case "GCM":
		return EncryptGCM(name, key, nonce, plaintext, aad)
	case "CCM":
		return EncryptSM4CCM(key, nonce, plaintext, aad)
	case "POLY1305":
		return EncryptChaCha20Poly1305(key, nonce, plaintext, aad)
	}
	return nil, nil, fmt.Errorf("sym: %q: %w: not an AEAD mode", name, ErrUnsupported)
}

// DecryptAEAD 按算法名 AEAD 解密。tag 或 aad 不匹配时返回错误；
// 调用方须将任意非 nil 错误视为认证失败并丢弃返回的明文。
// 支持的算法与参数要求同 EncryptAEAD。
//
// DecryptAEAD verifies and decrypts with the named AEAD algorithm. A tag
// or AAD mismatch yields an error; callers MUST treat any non-nil error
// as an authentication failure and discard the returned plaintext. The
// supported algorithms and parameter rules match EncryptAEAD.
func DecryptAEAD(name string, key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if a.size > 0 && len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch mode {
	case "GCM":
		return DecryptGCM(name, key, nonce, ciphertext, tag, aad)
	case "CCM":
		return DecryptSM4CCM(key, nonce, ciphertext, tag, aad)
	case "POLY1305":
		return DecryptChaCha20Poly1305(key, nonce, ciphertext, tag, aad)
	}
	return nil, fmt.Errorf("sym: %q: %w: not an AEAD mode", name, ErrUnsupported)
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
	case strings.HasPrefix(strings.ToUpper(name), "AES-"):
		return DecryptAESGCM(key, nonce, ciphertext, tag, aad)
	case strings.HasPrefix(strings.ToUpper(name), "SM4-"):
		return DecryptSM4GCM(key, nonce, ciphertext, tag, aad)
	}
	return nil, fmt.Errorf("sym: %q: %w", name, ErrUnsupported)
}

// Available 报告当前铜锁构建是否真的提供该「算法-模式」名。
// 与 Names() 的关系：Names() 是**编译期**清单（本库支持哪些），Available 是
// **运行时**事实（本机铜锁的 provider 能跑哪些）。典型差异：Tongsuo 8.4.0
// （OpenSSL 3.0.3 底座）没有 SM4-XTS（走 EVP_CIPHER_fetch），此时
// EncryptSM4XTS 返回「unavailable in this build」。
// name 大小写不敏感；未知名称返回 false。
//
// Available reports whether the installed Tongsuo build actually offers
// the named algorithm-mode. Names() is the compile-time list (what this
// library supports) whereas Available is the runtime fact (what the local
// providers can run). They differ in one typical case: Tongsuo 8.4.0
// (OpenSSL 3.0.3 base) has no SM4-XTS (it is fetched via
// EVP_CIPHER_fetch), and EncryptSM4XTS then reports "unavailable in this
// build". Matching is case-insensitive; unknown names return false.
func Available(name string) bool {
	a, _, err := lookup(name)
	if err != nil {
		return false
	}
	switch a.name {
	case "SM4-XTS":
		c := core.SM4XTS()
		if c == nil {
			return false
		}
		_ = c.Close()
		return true
	case "SM4-CCM":
		return core.SM4CCM() != nil
	case "ChaCha20":
		return core.ChaCha20() != nil
	case "ChaCha20-Poly1305":
		return core.ChaCha20Poly1305() != nil
	}
	if strings.HasPrefix(strings.ToUpper(a.name), "AES") {
		c, err := aesCipher(make([]byte, a.size), strings.ToLower(a.mode))
		return err == nil && c != nil
	}
	return sm4Cipher(strings.ToLower(a.mode)) != nil
}
