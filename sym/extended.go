package sym

import (
	"crypto/cipher"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

const (
	sivEmptyMinVersion   = 0x30500000
	maxNativeCipherInput = 1<<31 - 1
)

func extendedAESName(key []byte, mode string) (string, error) {
	size := len(key)
	bits := size * 8
	switch mode {
	case "SIV":
		if size != 32 && size != 48 && size != 64 {
			return "", fmt.Errorf("sym: AES-SIV: %w", ErrInvalidKeyLength)
		}
		bits /= 2
	case "XTS":
		if size != 32 && size != 64 {
			return "", fmt.Errorf("sym: AES-XTS: %w", ErrInvalidKeyLength)
		}
		bits /= 2
	default:
		if size != 16 && size != 24 && size != 32 {
			return "", fmt.Errorf("sym: AES-%s: %w", mode, ErrInvalidKeyLength)
		}
	}
	return fmt.Sprintf("AES-%d-%s", bits, mode), nil
}

func extendedCipher(a algo) bool {
	return a.name == "ZUC-128-EEA3" || (strings.HasPrefix(a.name, "AES-") && (a.mode == "XTS" || a.mode == "WRAP" || a.mode == "WRAP-PAD" || a.mode == "CBC-CTS"))
}

func cryptExtended(a algo, key, iv, data []byte, enc bool) ([]byte, error) {
	if len(key) != a.size {
		return nil, fmt.Errorf("sym: %s: %w", a.name, ErrInvalidKeyLength)
	}
	switch a.mode {
	case "XTS", "CBC-CTS":
		if len(data) < BlockSize {
			return nil, fmt.Errorf("sym: %s: input must contain at least one block", a.name)
		}
	case "WRAP":
		min := 16
		if !enc {
			min = 24
		}
		if len(data) < min || len(data)%8 != 0 {
			return nil, fmt.Errorf("sym: %s: invalid input length", a.name)
		}
	case "WRAP-PAD":
		if len(data) == 0 || (!enc && (len(data) < 16 || len(data)%8 != 0)) {
			return nil, fmt.Errorf("sym: %s: invalid input length", a.name)
		}
	}
	c := core.FetchCipher(a.name)
	if c == nil {
		return nil, fmt.Errorf("sym: %s: %w", a.name, ErrUnsupported)
	}
	defer c.Close()
	// nil selects the standard RFC 3394 / RFC 5649 initial value.
	if len(iv) == 0 && a.mode == "WRAP" {
		iv = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	}
	if len(iv) == 0 && a.mode == "WRAP-PAD" {
		iv = []byte{0xa6, 0x59, 0x59, 0xa6}
	}
	ctx, err := core.NewCipherCtx(c, key, iv, enc)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	if err = ctx.SetPadding(false); err != nil {
		return nil, err
	}
	if enc {
		return ctx.EncryptAll(data)
	}
	return ctx.DecryptAll(data)
}

func extendedAEADContext(a algo, key, nonce, tag []byte, n int, enc bool) (*core.CipherCtx, *core.Cipher, error) {
	if len(key) != a.size {
		return nil, nil, fmt.Errorf("sym: %s: %w", a.name, ErrInvalidKeyLength)
	}
	if !enc && len(tag) != TagSize {
		return nil, nil, fmt.Errorf("sym: invalid tag size %d", len(tag))
	}
	switch a.mode {
	case "CCM":
		if len(nonce) < 7 || len(nonce) > 13 {
			return nil, nil, fmt.Errorf("sym: invalid CCM nonce size %d", len(nonce))
		}
		l := 15 - len(nonce)
		if l < 8 && uint64(n) >= uint64(1)<<uint(8*l) {
			return nil, nil, fmt.Errorf("sym: CCM message too long")
		}
	case "GCM-SIV":
		if uint64(n) > uint64(maxNativeCipherInput-2*BlockSize) {
			return nil, nil, fmt.Errorf("sym: GCM-SIV message exceeds native input limit")
		}
		if len(nonce) != NonceSize {
			return nil, nil, fmt.Errorf("sym: GCM-SIV nonce must be %d bytes", NonceSize)
		}
	case "OCB":
		if len(nonce) < 1 || len(nonce) > 15 {
			return nil, nil, fmt.Errorf("sym: invalid OCB nonce size %d", len(nonce))
		}
	case "SIV":
		if n == 0 && core.VersionNum() < sivEmptyMinVersion {
			return nil, nil, fmt.Errorf("sym: AES-SIV requires a non-empty message on Tongsuo 8.4.0: %w", ErrUnsupported)
		}
	default:
		return nil, nil, fmt.Errorf("sym: %s: %w", a.name, ErrUnsupported)
	}
	c := core.FetchCipher(a.name)
	if c == nil {
		return nil, nil, fmt.Errorf("sym: %s: %w", a.name, ErrUnsupported)
	}
	var ctx *core.CipherCtx
	var err error
	if a.mode == "CCM" {
		ctx, err = core.NewCCMCtx(c, key, nonce, n, TagSize, enc)
		if err == nil && !enc {
			err = ctx.SetTag(tag)
		}
	} else {
		ctx, err = core.NewAEADCtx(c, key, nonce, tag, enc, a.mode == "SIV")
	}
	if err != nil {
		if ctx != nil {
			ctx.Close()
		}
		c.Close()
		return nil, nil, err
	}
	return ctx, c, nil
}

func encryptExtendedAEAD(a algo, key, nonce, data, aad []byte) ([]byte, []byte, error) {
	if a.mode == "GCM-SIV" && uint64(len(aad)) > uint64(maxNativeCipherInput) {
		return nil, nil, fmt.Errorf("sym: GCM-SIV AAD exceeds native input limit")
	}
	ctx, c, err := extendedAEADContext(a, key, nonce, nil, len(data), true)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	defer ctx.Close()
	if len(aad) > 0 {
		if err = ctx.SetAad(aad); err != nil {
			return nil, nil, err
		}
	}
	if a.mode == "SIV" && len(nonce) > 0 {
		if err = ctx.SetAad(nonce); err != nil {
			return nil, nil, err
		}
	}
	out, err := ctx.EncryptAll(data)
	if err != nil {
		return nil, nil, err
	}
	tag := make([]byte, TagSize)
	if err = ctx.GetTag(tag); err != nil {
		return nil, nil, err
	}
	return out, tag, nil
}

func decryptExtendedAEAD(a algo, key, nonce, data, tag, aad []byte) ([]byte, error) {
	if a.mode == "GCM-SIV" && uint64(len(aad)) > uint64(maxNativeCipherInput) {
		return nil, fmt.Errorf("sym: GCM-SIV AAD exceeds native input limit")
	}
	ctx, c, err := extendedAEADContext(a, key, nonce, tag, len(data), false)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	defer ctx.Close()
	if len(aad) > 0 {
		if err = ctx.SetAad(aad); err != nil {
			return nil, err
		}
	}
	if a.mode == "SIV" && len(nonce) > 0 {
		if err = ctx.SetAad(nonce); err != nil {
			return nil, err
		}
	}
	return ctx.DecryptAll(data)
}

type extendedAEAD struct {
	a   algo
	key []byte
}

func newExtendedAEAD(a algo, key []byte) (cipher.AEAD, error) {
	if len(key) != a.size {
		return nil, fmt.Errorf("sym: %s: %w", a.name, ErrInvalidKeyLength)
	}
	if !Available(a.name) {
		return nil, fmt.Errorf("sym: %s: %w", a.name, ErrUnsupported)
	}
	return &extendedAEAD{a, append([]byte(nil), key...)}, nil
}

// NonceSize 返回模式默认 nonce 长度（确定性 SIV 为 0）。
//
// NonceSize returns the default nonce length (zero for deterministic SIV).
func (g *extendedAEAD) NonceSize() int {
	if g.a.mode == "SIV" {
		return 0
	}
	return NonceSize
}

// Overhead 返回追加的 16 字节认证标签长度。
//
// Overhead returns the appended 16-byte authentication tag length.
func (g *extendedAEAD) Overhead() int { return TagSize }

// Seal 加密并追加 tag；参数或原生失败返回 nil。CCM/OCB 的 nonce 不得复用。
//
// Seal encrypts and appends a tag, returning nil on argument or native failure. Never reuse CCM/OCB nonces.
func (g *extendedAEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != g.NonceSize() {
		return nil
	}
	ct, tag, err := encryptExtendedAEAD(g.a, g.key, nonce, plaintext, aad)
	if err != nil {
		return nil
	}
	return append(append(dst, ct...), tag...)
}

// Open 校验标签后追加明文；认证或参数错误不返回部分明文。
//
// Open authenticates before appending plaintext; authentication or argument failures return no partial plaintext.
func (g *extendedAEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != g.NonceSize() || len(ciphertext) < TagSize {
		return nil, fmt.Errorf("sym: invalid nonce or ciphertext length")
	}
	n := len(ciphertext) - TagSize
	pt, err := decryptExtendedAEAD(g.a, g.key, nonce, ciphertext[:n], ciphertext[n:], aad)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}

// NewAESCCM 创建 AES-CCM AEAD，密钥长度为 16/24/32 字节。
// nonce 长度为 12；调用方负责清零源密钥。Seal 失败返回 nil。
// CCM/OCB 的 nonce 必须在同一密钥下唯一；认证失败返回错误。
//
// NewAESCCM creates AES-CCM with 16/24/32-byte keys.
// NonceSize is 12; callers must wipe source keys. Seal returns nil on failure.
// CCM/OCB nonces must be unique per key; authentication failures return errors.
func NewAESCCM(key []byte) (cipher.AEAD, error) {
	name, err := extendedAESName(key, "CCM")
	if err != nil {
		return nil, err
	}
	return NewAEAD(name, key)
}

// NewAESOCB 创建 AES-OCB AEAD，密钥长度为 16/24/32 字节。
// nonce 长度为 12；调用方负责清零源密钥。Seal 失败返回 nil。
// CCM/OCB 的 nonce 必须在同一密钥下唯一；认证失败返回错误。
//
// NewAESOCB creates AES-OCB with 16/24/32-byte keys.
// NonceSize is 12; callers must wipe source keys. Seal returns nil on failure.
// CCM/OCB nonces must be unique per key; authentication failures return errors.
func NewAESOCB(key []byte) (cipher.AEAD, error) {
	name, err := extendedAESName(key, "OCB")
	if err != nil {
		return nil, err
	}
	return NewAEAD(name, key)
}

// NewAESSIV 创建 AES-SIV AEAD，密钥长度为 32/48/64 字节。
// nonce 长度为 0（确定性 SIV）；调用方负责清零源密钥。Seal 失败返回 nil。
// CCM/OCB 的 nonce 必须在同一密钥下唯一；认证失败返回错误。
//
// NewAESSIV creates AES-SIV with 32/48/64-byte keys.
// NonceSize is zero (deterministic SIV); callers must wipe source keys. Seal returns nil on failure.
// CCM/OCB nonces must be unique per key; authentication failures return errors.
func NewAESSIV(key []byte) (cipher.AEAD, error) {
	name, err := extendedAESName(key, "SIV")
	if err != nil {
		return nil, err
	}
	return NewAEAD(name, key)
}

// EncryptAESCCM 使用 AES-CCM 加密并返回密文与 16 字节 tag。
// CCM 的 nonce 为 7..13 字节，OCB 为 1..15 字节；SIV 将 nonce 作为最后一个 AAD 分量。
// CCM/OCB 不得复用 nonce；调用方负责清零源密钥；失败返回错误。
//
// EncryptAESCCM encrypts and returns ciphertext and a 16-byte tag with AES-CCM.
// CCM accepts 7..13-byte nonces and OCB 1..15; SIV treats nonce as the last AAD component.
// Never reuse CCM/OCB nonces; callers must wipe source keys. Failures return errors.
func EncryptAESCCM(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	name, err := extendedAESName(key, "CCM")
	if err != nil {
		return nil, nil, err
	}
	a, _, err := lookup(name)
	if err != nil {
		return nil, nil, err
	}
	return encryptExtendedAEAD(a, key, nonce, plaintext, aad)
}

// DecryptAESCCM 使用 AES-CCM 校验 tag 并解密。
// CCM 的 nonce 为 7..13 字节，OCB 为 1..15 字节；SIV 将 nonce 作为最后一个 AAD 分量。
// CCM/OCB 不得复用 nonce；调用方负责清零源密钥；失败返回错误。
//
// DecryptAESCCM authenticates and decrypts with AES-CCM.
// CCM accepts 7..13-byte nonces and OCB 1..15; SIV treats nonce as the last AAD component.
// Never reuse CCM/OCB nonces; callers must wipe source keys. Failures return errors.
func DecryptAESCCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	name, err := extendedAESName(key, "CCM")
	if err != nil {
		return nil, err
	}
	a, _, err := lookup(name)
	if err != nil {
		return nil, err
	}
	return decryptExtendedAEAD(a, key, nonce, ciphertext, tag, aad)
}

// EncryptAESOCB 使用 AES-OCB 加密并返回密文与 16 字节 tag。
// CCM 的 nonce 为 7..13 字节，OCB 为 1..15 字节；SIV 将 nonce 作为最后一个 AAD 分量。
// CCM/OCB 不得复用 nonce；调用方负责清零源密钥；失败返回错误。
//
// EncryptAESOCB encrypts and returns ciphertext and a 16-byte tag with AES-OCB.
// CCM accepts 7..13-byte nonces and OCB 1..15; SIV treats nonce as the last AAD component.
// Never reuse CCM/OCB nonces; callers must wipe source keys. Failures return errors.
func EncryptAESOCB(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	name, err := extendedAESName(key, "OCB")
	if err != nil {
		return nil, nil, err
	}
	a, _, err := lookup(name)
	if err != nil {
		return nil, nil, err
	}
	return encryptExtendedAEAD(a, key, nonce, plaintext, aad)
}

// DecryptAESOCB 使用 AES-OCB 校验 tag 并解密。
// CCM 的 nonce 为 7..13 字节，OCB 为 1..15 字节；SIV 将 nonce 作为最后一个 AAD 分量。
// CCM/OCB 不得复用 nonce；调用方负责清零源密钥；失败返回错误。
//
// DecryptAESOCB authenticates and decrypts with AES-OCB.
// CCM accepts 7..13-byte nonces and OCB 1..15; SIV treats nonce as the last AAD component.
// Never reuse CCM/OCB nonces; callers must wipe source keys. Failures return errors.
func DecryptAESOCB(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	name, err := extendedAESName(key, "OCB")
	if err != nil {
		return nil, err
	}
	a, _, err := lookup(name)
	if err != nil {
		return nil, err
	}
	return decryptExtendedAEAD(a, key, nonce, ciphertext, tag, aad)
}

// EncryptAESSIV 使用 AES-SIV 加密并返回密文与 16 字节 tag。
// CCM 的 nonce 为 7..13 字节，OCB 为 1..15 字节；SIV 将 nonce 作为最后一个 AAD 分量。
// CCM/OCB 不得复用 nonce；调用方负责清零源密钥；失败返回错误。
//
// EncryptAESSIV encrypts and returns ciphertext and a 16-byte tag with AES-SIV.
// CCM accepts 7..13-byte nonces and OCB 1..15; SIV treats nonce as the last AAD component.
// Never reuse CCM/OCB nonces; callers must wipe source keys. Failures return errors.
func EncryptAESSIV(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	name, err := extendedAESName(key, "SIV")
	if err != nil {
		return nil, nil, err
	}
	a, _, err := lookup(name)
	if err != nil {
		return nil, nil, err
	}
	return encryptExtendedAEAD(a, key, nonce, plaintext, aad)
}

// DecryptAESSIV 使用 AES-SIV 校验 tag 并解密。
// CCM 的 nonce 为 7..13 字节，OCB 为 1..15 字节；SIV 将 nonce 作为最后一个 AAD 分量。
// CCM/OCB 不得复用 nonce；调用方负责清零源密钥；失败返回错误。
//
// DecryptAESSIV authenticates and decrypts with AES-SIV.
// CCM accepts 7..13-byte nonces and OCB 1..15; SIV treats nonce as the last AAD component.
// Never reuse CCM/OCB nonces; callers must wipe source keys. Failures return errors.
func DecryptAESSIV(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	name, err := extendedAESName(key, "SIV")
	if err != nil {
		return nil, err
	}
	a, _, err := lookup(name)
	if err != nil {
		return nil, err
	}
	return decryptExtendedAEAD(a, key, nonce, ciphertext, tag, aad)
}

// EncryptAESXTS 使用 AES-XTS；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// EncryptAESXTS uses AES-XTS; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func EncryptAESXTS(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "XTS")
	if err != nil {
		return nil, err
	}
	return Encrypt(name, key, iv, data, nil)
}

// DecryptAESXTS 使用 AES-XTS；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// DecryptAESXTS uses AES-XTS; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func DecryptAESXTS(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "XTS")
	if err != nil {
		return nil, err
	}
	return Decrypt(name, key, iv, data, nil)
}

// EncryptAESWrap 使用 AES-WRAP；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// EncryptAESWrap uses AES-WRAP; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func EncryptAESWrap(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "WRAP")
	if err != nil {
		return nil, err
	}
	return Encrypt(name, key, iv, data, nil)
}

// DecryptAESWrap 使用 AES-WRAP；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// DecryptAESWrap uses AES-WRAP; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func DecryptAESWrap(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "WRAP")
	if err != nil {
		return nil, err
	}
	return Decrypt(name, key, iv, data, nil)
}

// EncryptAESWrapPad 使用 AES-WRAP-PAD；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// EncryptAESWrapPad uses AES-WRAP-PAD; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func EncryptAESWrapPad(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "WRAP-PAD")
	if err != nil {
		return nil, err
	}
	return Encrypt(name, key, iv, data, nil)
}

// DecryptAESWrapPad 使用 AES-WRAP-PAD；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// DecryptAESWrapPad uses AES-WRAP-PAD; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func DecryptAESWrapPad(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "WRAP-PAD")
	if err != nil {
		return nil, err
	}
	return Decrypt(name, key, iv, data, nil)
}

// EncryptAESCBCCTS 使用 AES-CBC-CTS；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// EncryptAESCBCCTS uses AES-CBC-CTS; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func EncryptAESCBCCTS(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "CBC-CTS")
	if err != nil {
		return nil, err
	}
	return Encrypt(name, key, iv, data, nil)
}

// DecryptAESCBCCTS 使用 AES-CBC-CTS；iv 为模式 IV（WRAP 可传 nil 使用标准值）。
// XTS 使用双倍密钥；CBC-CTS 默认 CS1。调用方负责清零源密钥；失败返回错误。
//
// DecryptAESCBCCTS uses AES-CBC-CTS; iv is the mode IV (nil selects the standard WRAP IV).
// XTS uses doubled keys; CBC-CTS defaults to CS1. Callers must wipe source keys; failures return errors.
func DecryptAESCBCCTS(key, iv, data []byte) ([]byte, error) {
	name, err := extendedAESName(key, "CBC-CTS")
	if err != nil {
		return nil, err
	}
	return Decrypt(name, key, iv, data, nil)
}

// EncryptZUC 使用 ZUC-128-EEA3，key 为 16 字节，iv 为 5 字节（COUNT 大端 4 字节 + bearer/direction 字节）；不得复用 key/iv。
// 调用方负责清零源密钥；失败返回错误。
//
// EncryptZUC uses ZUC-128-EEA3 with a 16-byte key and 5-byte IV (4-byte big-endian COUNT plus bearer/direction); never reuse key/IV pairs.
// Callers must wipe source keys; failures return errors.
func EncryptZUC(key, iv, data []byte) ([]byte, error) {
	return Encrypt("ZUC-128-EEA3", key, iv, data, nil)
}

// DecryptZUC 使用 ZUC-128-EEA3，key 为 16 字节，iv 为 5 字节（COUNT 大端 4 字节 + bearer/direction 字节）；不得复用 key/iv。
// 调用方负责清零源密钥；失败返回错误。
//
// DecryptZUC uses ZUC-128-EEA3 with a 16-byte key and 5-byte IV (4-byte big-endian COUNT plus bearer/direction); never reuse key/IV pairs.
// Callers must wipe source keys; failures return errors.
func DecryptZUC(key, iv, data []byte) ([]byte, error) {
	return Decrypt("ZUC-128-EEA3", key, iv, data, nil)
}
