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
	// 取值是否与算法名相容可用 Supports / Paddings 静态查询：分组模式
	// （ECB / CBC）支持三者，流模式（CTR / OFB / CFB / ChaCha20 / XTS）
	// 只接受""与 "none"，非法组合返回 ErrUnsupportedPadding。
	//
	// Padding is "pkcs7" (default) / "zero" / "none". Use Supports or
	// Paddings to query statically whether a value is valid for a given
	// algorithm name: block modes (ECB / CBC) accept all three, stream
	// modes (CTR / OFB / CFB / ChaCha20 / XTS) accept only "" and
	// "none", and invalid combinations return ErrUnsupportedPadding.
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
	{"AES-128-CFB", AES128KeySize, "CFB"},
	{"AES-128-CTR", AES128KeySize, "CTR"},
	{"AES-128-ECB", AES128KeySize, "ECB"},
	{"AES-128-GCM", AES128KeySize, "GCM"},
	{"AES-128-GCM-SIV", AES128KeySize, "GCM-SIV"},
	{"AES-128-OFB", AES128KeySize, "OFB"},
	{"AES-192-CBC", AES192KeySize, "CBC"},
	{"AES-192-CFB", AES192KeySize, "CFB"},
	{"AES-192-CTR", AES192KeySize, "CTR"},
	{"AES-192-ECB", AES192KeySize, "ECB"},
	{"AES-192-GCM", AES192KeySize, "GCM"},
	{"AES-192-GCM-SIV", AES192KeySize, "GCM-SIV"},
	{"AES-192-OFB", AES192KeySize, "OFB"},
	{"AES-256-CBC", AES256KeySize, "CBC"},
	{"AES-256-CFB", AES256KeySize, "CFB"},
	{"AES-256-CTR", AES256KeySize, "CTR"},
	{"AES-256-ECB", AES256KeySize, "ECB"},
	{"AES-256-GCM", AES256KeySize, "GCM"},
	{"AES-256-GCM-SIV", AES256KeySize, "GCM-SIV"},
	{"AES-256-OFB", AES256KeySize, "OFB"},
	{"DES-CBC", DESKeySize, "CBC"},
	{"DES-ECB", DESKeySize, "ECB"},
	{"DES-EDE-CBC", DESEDEKeySize, "CBC"},
	{"DES-EDE-ECB", DESEDEKeySize, "ECB"},
	{"DES-EDE3-CBC", DESEDE3KeySize, "CBC"},
	{"DES-EDE3-ECB", DESEDE3KeySize, "ECB"},
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
	{"AES-128-CCM", 16, "CCM"},
	{"AES-128-OCB", 16, "OCB"},
	{"AES-128-SIV", 32, "SIV"},
	{"AES-128-WRAP", 16, "WRAP"},
	{"AES-128-WRAP-PAD", 16, "WRAP-PAD"},
	{"AES-128-CBC-CTS", 16, "CBC-CTS"},
	{"AES-128-XTS", 32, "XTS"},
	{"AES-192-CCM", 24, "CCM"},
	{"AES-192-OCB", 24, "OCB"},
	{"AES-192-SIV", 48, "SIV"},
	{"AES-192-WRAP", 24, "WRAP"},
	{"AES-192-WRAP-PAD", 24, "WRAP-PAD"},
	{"AES-192-CBC-CTS", 24, "CBC-CTS"},
	{"AES-256-CCM", 32, "CCM"},
	{"AES-256-OCB", 32, "OCB"},
	{"AES-256-SIV", 64, "SIV"},
	{"AES-256-WRAP", 32, "WRAP"},
	{"AES-256-WRAP-PAD", 32, "WRAP-PAD"},
	{"AES-256-CBC-CTS", 32, "CBC-CTS"},
	{"AES-256-XTS", 64, "XTS"},
	{"ZUC-128-EEA3", 16, "STREAM"},
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
	name = a.name

	switch mode {
	case "GCM", "CCM", "POLY1305", "OCB", "SIV", "GCM-SIV":
		return nil, fmt.Errorf("sym: %q: %w: cipher.Block is not applicable to AEAD modes", name, ErrUnsupported)
	case "XTS", "STREAM", "WRAP", "WRAP-PAD", "CBC-CTS":
		return nil, fmt.Errorf("sym: %q: %w: cipher.Block is not applicable to mode %s", name, ErrUnsupported, mode)
	}
	if a.size > 0 && len(key) != a.size {
		return nil, fmt.Errorf("sym: %q: %w: key size %d, want %d", name, ErrInvalidKeyLength, len(key), a.size)
	}
	switch {
	case strings.HasPrefix(strings.ToUpper(name), "AES-"):
		return NewAESCipher(key)
	case strings.HasPrefix(strings.ToUpper(name), "DES-EDE3-"):
		return newDESBlock(desEDE3, key)
	case strings.HasPrefix(strings.ToUpper(name), "DES-EDE-"):
		return newDESBlock(desEDE, key)
	case strings.HasPrefix(strings.ToUpper(name), "DES-"):
		return NewDESCipher(key)
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
	name = a.name

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
// 0.6.0 另支持 AES-CCM/OCB/SIV；SIV 为双密钥、默认 nonce 长度为 0，拒绝空消息。
// 0.8.0 新增 GCM-SIV；铜锁 8.5.0 支持 SIV 空消息认证，8.4.0 仍拒绝。
//
// NewAEAD returns a cipher.AEAD by algorithm-mode name. It supports GCM
// (AES-128/192/256, SM4), CCM (SM4) and ChaCha20-Poly1305. Unknown names
// return ErrUnknownAlgorithm; non-AEAD modes return ErrUnsupported.
// Version 0.6.0 also supports AES-CCM/OCB/SIV; SIV uses doubled keys and a zero default nonce size, rejecting empty messages.
// Version 0.8.0 adds GCM-SIV; Tongsuo 8.5.0 authenticates empty SIV messages, while 8.4.0 rejects them.
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
		if strings.HasPrefix(a.name, "AES-") {
			return newExtendedAEAD(a, key)
		}
		return NewSM4CCM(key)
	case "OCB", "SIV", "GCM-SIV":
		return newExtendedAEAD(a, key)
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
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	name = a.name
	if len(key) != a.size {
		return nil, fmt.Errorf("sym: %s: %w", name, ErrInvalidKeyLength)
	}

	switch mode {
	case "GCM", "CCM", "POLY1305", "OCB", "SIV", "GCM-SIV":
		return nil, fmt.Errorf("sym: %q: %w: use EncryptAEAD", name, ErrUnsupported)
	}
	pad := ""
	if opts != nil {
		pad = opts.Padding
	}
	pad, err = checkPadding(name, mode, pad)
	if err != nil {
		return nil, err
	}

	if extendedCipher(a) {
		return cryptExtended(a, key, iv, data, true)
	}

	switch strings.ToUpper(name) {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return aesCryptWithPad(key, iv, data, true, "cbc", pad)
	case "AES-128-CTR", "AES-192-CTR", "AES-256-CTR":
		return EncryptAESCTR(key, iv, data)
	case "AES-128-ECB", "AES-192-ECB", "AES-256-ECB":
		return aesCryptWithPad(key, nil, data, true, "ecb", pad)
	case "AES-128-OFB", "AES-192-OFB", "AES-256-OFB":
		return EncryptAESOFB(key, iv, data)
	case "AES-128-CFB", "AES-192-CFB", "AES-256-CFB":
		return EncryptAESCFB(key, iv, data)
	case "DES-ECB":
		return desCryptWithPad(key, nil, data, true, desSingle, "ecb", pad)
	case "DES-CBC":
		return desCryptWithPad(key, iv, data, true, desSingle, "cbc", pad)
	case "DES-EDE-ECB":
		return desCryptWithPad(key, nil, data, true, desEDE, "ecb", pad)
	case "DES-EDE-CBC":
		return desCryptWithPad(key, iv, data, true, desEDE, "cbc", pad)
	case "DES-EDE3-ECB":
		return desCryptWithPad(key, nil, data, true, desEDE3, "ecb", pad)
	case "DES-EDE3-CBC":
		return desCryptWithPad(key, iv, data, true, desEDE3, "cbc", pad)
	case "SM4-CBC":
		return sm4CryptWithPad(key, iv, data, true, "cbc", pad)
	case "SM4-CTR":
		return EncryptSM4CTR(key, iv, data)
	case "SM4-ECB":
		return sm4CryptWithPad(key, nil, data, true, "ecb", pad)
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
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	name = a.name
	if len(key) != a.size {
		return nil, fmt.Errorf("sym: %s: %w", name, ErrInvalidKeyLength)
	}

	switch mode {
	case "GCM", "CCM", "POLY1305", "OCB", "SIV", "GCM-SIV":
		return nil, fmt.Errorf("sym: %q: %w: use DecryptAEAD", name, ErrUnsupported)
	}
	pad := ""
	if opts != nil {
		pad = opts.Padding
	}
	pad, err = checkPadding(name, mode, pad)
	if err != nil {
		return nil, err
	}
	if extendedCipher(a) {
		return cryptExtended(a, key, iv, data, false)
	}

	switch strings.ToUpper(name) {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return aesCryptWithPad(key, iv, data, false, "cbc", pad)
	case "AES-128-CTR", "AES-192-CTR", "AES-256-CTR":
		return DecryptAESCTR(key, iv, data)
	case "AES-128-ECB", "AES-192-ECB", "AES-256-ECB":
		return aesCryptWithPad(key, nil, data, false, "ecb", pad)
	case "AES-128-OFB", "AES-192-OFB", "AES-256-OFB":
		return DecryptAESOFB(key, iv, data)
	case "AES-128-CFB", "AES-192-CFB", "AES-256-CFB":
		return DecryptAESCFB(key, iv, data)
	case "DES-ECB":
		return desCryptWithPad(key, nil, data, false, desSingle, "ecb", pad)
	case "DES-CBC":
		return desCryptWithPad(key, iv, data, false, desSingle, "cbc", pad)
	case "DES-EDE-ECB":
		return desCryptWithPad(key, nil, data, false, desEDE, "ecb", pad)
	case "DES-EDE-CBC":
		return desCryptWithPad(key, iv, data, false, desEDE, "cbc", pad)
	case "DES-EDE3-ECB":
		return desCryptWithPad(key, nil, data, false, desEDE3, "ecb", pad)
	case "DES-EDE3-CBC":
		return desCryptWithPad(key, iv, data, false, desEDE3, "cbc", pad)
	case "SM4-CBC":
		return sm4CryptWithPad(key, iv, data, false, "cbc", pad)
	case "SM4-CTR":
		return DecryptSM4CTR(key, iv, data)
	case "SM4-ECB":
		return sm4CryptWithPad(key, nil, data, false, "ecb", pad)
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

// checkPadding 校验「算法名 × 填充」组合，并返回归一后的填充名。
// 未知填充名与不相容组合均返回包装 ErrUnsupportedPadding 的错误。
//
// checkPadding validates the algorithm-name/padding combination and
// returns the normalized padding. Both unknown padding names and
// incompatible combinations return an error wrapping
// ErrUnsupportedPadding.
func checkPadding(name, mode, pad string) (string, error) {
	norm, err := normalizePadding(pad)
	if err != nil {
		return "", fmt.Errorf("sym: %q: %w", name, err)
	}
	allowed := paddingsForMode(mode)
	if norm == "" {
		// 空串：取该模式的默认值（分组模式 pkcs7，流模式 none）。
		if len(allowed) > 0 {
			if len(allowed) == 3 {
				return PaddingPKCS7, nil
			}
			return allowed[0], nil
		}
		return PaddingNone, nil
	}
	for _, p := range allowed {
		if p == norm {
			return norm, nil
		}
	}
	return "", fmt.Errorf("sym: %q: padding %q is not supported for mode %s: %w",
		name, norm, mode, ErrUnsupportedPadding)
}

// Supports 报告「算法名 × 填充」是否为合法组合，可在不提交数据的前提下做参数级
// 校验。空串等价于 "pkcs7"。
// 未知算法名返回 ErrUnknownAlgorithm；未知填充名与不相容组合返回 (false, nil)。
// 返回 true 的取值与 Paddings 一致。
//
// Supports reports whether an algorithm-name/padding combination is
// valid, so callers can validate parameters without submitting data. The
// empty string means "pkcs7". An unknown algorithm name returns
// ErrUnknownAlgorithm; an unknown padding name or an incompatible
// combination returns (false, nil). The accepted values match Paddings.
func Supports(name, padding string) (bool, error) {
	a, _, err := lookup(name)
	if err != nil {
		return false, err
	}
	norm, err := normalizePadding(padding)
	if err != nil {
		return false, nil
	}
	if norm == "" {
		// 空串表示「用默认值」，任何已知算法名都接受。
		return true, nil
	}
	for _, p := range paddingsForMode(a.mode) {
		if p == norm {
			return true, nil
		}
	}
	return false, nil
}

// Paddings 返回该算法名可用的填充方式（顺序稳定）。
// 分组模式（ECB / CBC）返回 pkcs7 / zero / none；流模式（CTR / OFB / CFB /
// ChaCha20）与 XTS 返回 none；AEAD 模式（GCM / CCM / ChaCha20-Poly1305）返回
// 空切片——它们走 EncryptAEAD，不经过填充层。
// 未知算法名返回 ErrUnknownAlgorithm。
//
// Paddings returns the padding modes available for the named algorithm
// in a stable order. Block modes (ECB / CBC) return pkcs7 / zero / none;
// stream modes (CTR / OFB / CFB / ChaCha20) and XTS return none; AEAD
// modes (GCM / CCM / ChaCha20-Poly1305) return an empty slice because
// they are driven through EncryptAEAD and never reach the padding layer.
// An unknown name returns ErrUnknownAlgorithm.
func Paddings(name string) ([]string, error) {
	a, _, err := lookup(name)
	if err != nil {
		return nil, err
	}
	out := paddingsForMode(a.mode)
	if out == nil {
		return []string{}, nil
	}
	return out, nil
}

// sm4CryptWithPad 按填充方式驱动 SM4 分组成模式（ECB / CBC）的加解密。
//
// sm4CryptWithPad drives SM4 ECB / CBC with the requested padding.
func sm4CryptWithPad(key, iv, data []byte, enc bool, mode, pad string) ([]byte, error) {
	c := sm4Cipher(mode)
	if c == nil {
		return nil, fmt.Errorf("sym: SM4 unsupported mode %q", mode)
	}
	if mode == "ecb" {
		iv = nil
	} else if len(iv) != BlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), BlockSize)
	}
	return cryptPadded(c, key, iv, data, enc, pad, BlockSize)
}

// EncryptGCM 按算法名 GCM 加密，返回密文与认证标签。
//
// EncryptGCM encrypts in one shot with GCM by algorithm-mode name.
func EncryptGCM(name string, key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, nil, err
	}
	name = a.name
	if len(key) != a.size {
		return nil, nil, fmt.Errorf("sym: %s: %w", name, ErrInvalidKeyLength)
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
// 0.6.0 另支持 AES-CCM/OCB/SIV；SIV 空消息返回 ErrUnsupported，非空 nonce 作为最后一个 AAD 分量。
//
// 安全：nonce 必须在每个 (key, message) 对中唯一；复用会同时破坏
// 机密性与真实性。
// 0.8.0 新增 GCM-SIV；铜锁 8.5.0 支持 SIV 空消息认证，8.4.0 仍拒绝。
//
// EncryptAEAD encrypts in one shot with the named AEAD algorithm and
// returns ciphertext and tag. It supports GCM (AES-128/192/256, SM4),
// CCM (SM4) and ChaCha20-Poly1305. Nonce length: 12 for GCM (other
// non-empty lengths are tolerated), 7 to 13 for CCM, and exactly 12 for
// ChaCha20-Poly1305; the tag is always TagSize (16) bytes. Unknown names
// return ErrUnknownAlgorithm; non-AEAD modes return ErrUnsupported.
// Version 0.6.0 also supports AES-CCM/OCB/SIV; empty SIV messages return ErrUnsupported and a nonempty SIV nonce is the last AAD component.
//
// Security: the nonce MUST be unique per (key, message) pair; reuse
// breaks both confidentiality and authenticity.
// Version 0.8.0 adds GCM-SIV; Tongsuo 8.5.0 authenticates empty SIV messages, while 8.4.0 rejects them.
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
		if strings.HasPrefix(a.name, "AES-") {
			return encryptExtendedAEAD(a, key, nonce, plaintext, aad)
		}
		return EncryptSM4CCM(key, nonce, plaintext, aad)
	case "OCB", "SIV", "GCM-SIV":
		return encryptExtendedAEAD(a, key, nonce, plaintext, aad)
	case "POLY1305":
		return EncryptChaCha20Poly1305(key, nonce, plaintext, aad)
	}
	return nil, nil, fmt.Errorf("sym: %q: %w: not an AEAD mode", name, ErrUnsupported)
}

// DecryptAEAD 按算法名 AEAD 解密。tag 或 aad 不匹配时返回错误；
// 调用方须将任意非 nil 错误视为认证失败并丢弃返回的明文。
// 支持的算法与参数要求同 EncryptAEAD。
// 0.6.0 另支持 AES-CCM/OCB/SIV；SIV 空消息返回 ErrUnsupported，非空 nonce 作为最后一个 AAD 分量。
// 0.8.0 新增 GCM-SIV；铜锁 8.5.0 支持 SIV 空消息认证，8.4.0 仍拒绝。
//
// DecryptAEAD verifies and decrypts with the named AEAD algorithm. A tag
// or AAD mismatch yields an error; callers MUST treat any non-nil error
// as an authentication failure and discard the returned plaintext. The
// supported algorithms and parameter rules match EncryptAEAD.
// Version 0.6.0 also supports AES-CCM/OCB/SIV; empty SIV messages return ErrUnsupported and a nonempty SIV nonce is the last AAD component.
// Version 0.8.0 adds GCM-SIV; Tongsuo 8.5.0 authenticates empty SIV messages, while 8.4.0 rejects them.
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
		if strings.HasPrefix(a.name, "AES-") {
			return decryptExtendedAEAD(a, key, nonce, ciphertext, tag, aad)
		}
		return DecryptSM4CCM(key, nonce, ciphertext, tag, aad)
	case "OCB", "SIV", "GCM-SIV":
		return decryptExtendedAEAD(a, key, nonce, ciphertext, tag, aad)
	case "POLY1305":
		return DecryptChaCha20Poly1305(key, nonce, ciphertext, tag, aad)
	}
	return nil, fmt.Errorf("sym: %q: %w: not an AEAD mode", name, ErrUnsupported)
}

// DecryptGCM 按算法名 GCM 解密。tag 校验失败时返回错误。
func DecryptGCM(name string, key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	a, mode, err := lookup(name)
	if err != nil {
		return nil, err
	}
	name = a.name
	if len(key) != a.size {
		return nil, fmt.Errorf("sym: %s: %w", name, ErrInvalidKeyLength)
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
	if extendedCipher(a) || a.mode == "CCM" || a.mode == "OCB" || a.mode == "SIV" || a.mode == "GCM-SIV" {
		c := core.FetchCipher(a.name)
		if c == nil {
			return false
		}
		defer c.Close()
		return true
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
	if strings.HasPrefix(strings.ToUpper(a.name), "DES") {
		var kind desKind
		switch {
		case strings.HasPrefix(strings.ToUpper(a.name), "DES-EDE3-"):
			kind = desEDE3
		case strings.HasPrefix(strings.ToUpper(a.name), "DES-EDE-"):
			kind = desEDE
		default:
			kind = desSingle
		}
		var c *core.Cipher
		switch a.mode {
		case "ECB":
			c = desCipher(kind, "ecb")
		case "CBC":
			c = desCipher(kind, "cbc")
		}
		return c != nil
	}
	return sm4Cipher(strings.ToLower(a.mode)) != nil
}
