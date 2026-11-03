package sym

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// 填充方式常量。与 Options.Padding 的字符串取值一一对应。
//
// Padding mode constants; they match the string values accepted by
// Options.Padding.
const (
	// PaddingPKCS7 为 PKCS#7 填充（分组模式默认值）：总会补足一个完整分组，
	// 因此密文长度严格大于明文长度。
	//
	// PaddingPKCS7 is PKCS#7 padding (the block-mode default): it always
	// adds a complete padding block, so the ciphertext is strictly longer
	// than the plaintext.
	PaddingPKCS7 = "pkcs7"

	// PaddingZero 为零填充：加密时在尾部补 0x00 补足到分组长度的整数倍
	// （已对齐时不追加整块）。解密不做剥离——尾部 0x00 无法与真实明文区分，
	// 调用方须自行按已知明文长度截断。
	//
	// PaddingZero pads the plaintext with 0x00 up to a block boundary
	// (nothing is appended when it is already aligned). Decryption does
	// NOT strip anything: trailing 0x00 bytes are indistinguishable from
	// real plaintext, so callers MUST truncate using a known length.
	PaddingZero = "zero"

	// PaddingNone 表示不做任何补齐与剥离：加密与解密的输入长度都必须是
	// 分组长度的整数倍，否则返回错误。
	//
	// PaddingNone performs neither padding nor stripping: both the
	// plaintext and the ciphertext length must be a multiple of the block
	// size, otherwise an error is returned.
	PaddingNone = "none"
)

// ErrUnsupportedPadding 报告「算法名 × 填充方式」的组合不被支持。
// 可用 Supports / Paddings 静态查询合法组合，无需先发数据。
//
// ErrUnsupportedPadding reports an unsupported algorithm-name/padding
// combination. Use Supports or Paddings to query the valid combinations
// statically, without submitting any data.
var ErrUnsupportedPadding = errors.New("sym: unsupported padding")

// normalizePadding 校验填充名取值并原样返回；空串保持为空（表示「用该模式的
// 默认值」，由 checkPadding 按模式解析）。未知取值返回 ErrUnsupportedPadding。
//
// normalizePadding validates the padding name and returns it unchanged;
// the empty string stays empty (meaning "use the mode's default", which
// checkPadding resolves per mode). Unknown values return
// ErrUnsupportedPadding.
func normalizePadding(pad string) (string, error) {
	switch pad {
	case "", PaddingPKCS7, PaddingZero, PaddingNone:
		return pad, nil
	}
	return "", fmt.Errorf("sym: padding %q: %w", pad, ErrUnsupportedPadding)
}

// zeroPad 把 data 补零到分组长度的整数倍（已对齐时返回原始切片）。
//
// zeroPad appends 0x00 up to a block boundary (returns the input slice
// unchanged when already aligned).
func zeroPad(data []byte, blockSize int) []byte {
	if rem := len(data) % blockSize; rem != 0 {
		out := make([]byte, len(data)+blockSize-rem)
		copy(out, data)
		return out
	}
	return data
}

// cryptPadded 按填充方式驱动一次分组成模式的加解密。
// 支持的填充为 PKCS#7 / zero / none；未知值返回 ErrUnsupportedPadding，
// none 与 zero 下长度未对齐返回错误。
// c 为算法描述符，blockSize 为该算法的分组长度（AES/SM4 为 16，DES 为 8）。
//
// cryptPadded runs a block-mode encrypt/decrypt with the requested
// padding. PKCS#7, zero and none are accepted; unknown values return
// ErrUnsupportedPadding and unaligned input under none returns an error.
// c is the cipher descriptor and blockSize its block length (16 for
// AES/SM4, 8 for DES).
func cryptPadded(c *core.Cipher, key, iv, data []byte, enc bool, pad string, blockSize int) ([]byte, error) {
	mode, err := normalizePadding(pad)
	if err != nil {
		return nil, err
	}
	if mode == "" {
		mode = PaddingPKCS7
	}
	switch mode {
	case PaddingNone:
		if rem := len(data) % blockSize; rem != 0 {
			return nil, fmt.Errorf("sym: padding none: input length %d is not a multiple of the block size %d", len(data), blockSize)
		}
	case PaddingZero:
		if enc {
			data = zeroPad(data, blockSize)
		}
	}

	ctx, err := core.NewCipherCtx(c, key, iv, enc)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if mode != PaddingPKCS7 {
		if err := ctx.SetPadding(false); err != nil {
			return nil, err
		}
	}
	if enc {
		return ctx.EncryptAll(data)
	}
	return ctx.DecryptAll(data)
}

// paddingsForMode 返回某模式族可用的填充方式（顺序稳定）。
// blockModes 为 true 时返回 pkcs7 / zero / none，否则只返回 none；
// AEAD 模式返回空切片（其加密走 EncryptAEAD，不经过填充层）。
//
// paddingsForMode returns the padding modes available to a mode family
// in a stable order: pkcs7 / zero / none for block modes, only none for
// stream-like modes, and an empty slice for AEAD modes (which are
// encrypted through EncryptAEAD and never reach the padding layer).
func paddingsForMode(mode string) []string {
	switch mode {
	case "ECB", "CBC":
		return []string{PaddingPKCS7, PaddingZero, PaddingNone}
	case "CTR", "OFB", "CFB", "XTS", "STREAM", "WRAP", "WRAP-PAD", "CBC-CTS":
		return []string{PaddingNone}
	}
	return nil
}
