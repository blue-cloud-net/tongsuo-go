package sym

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// DES 家族的实现说明（必读）
//
// 铜锁（OpenSSL 3 底座）把**单 DES**（DES-ECB / DES-CBC 等）只注册在 legacy
// provider 中，而加载 legacy provider 会为整个进程全局启用 RC4 / RC5 / DESX
// 等弱算法（见 docs/roadmap.md §4）。因此本库**不加载 legacy**，改为：
//
//   - 3DES：直接使用 default provider 的 DES-EDE3-*；
//   - 单 DES：把 8 字节密钥复制三份（K‖K‖K）驱动 DES-EDE3-*。三个子密钥相同时
//     EDE 三步退化为单个 DES，输出与真正的单 DES **逐字节相同**。
//
// 对外仍以 DES-ECB / DES-CBC 命名；差异仅在于底层的算法描述符。
//
// 安全：单 DES 的有效密钥仅 56 位，已可被穷举；2 密钥 3DES 约 80 位。两者都
// **仅用于兼容既有数据**，不得用于新协议。
//
// DES family implementation notes (MUST read)
//
// Tongsuo (OpenSSL 3 based) registers **single DES** (DES-ECB / DES-CBC and
// friends) only in the legacy provider, and loading that provider enables
// RC4 / RC5 / DESX process-wide (see docs/roadmap.md section 4). This
// library therefore never loads legacy; instead:
//
//   - 3DES uses the default provider's DES-EDE3-* directly;
//   - single DES replicates the 8-byte key three times (K‖K‖K) and drives
//     DES-EDE3-*. With three identical subkeys the EDE steps collapse into
//     one DES, so the output is **byte-identical** to real single DES.
//
// The public names stay DES-ECB / DES-CBC; only the underlying descriptor
// differs.
//
// Security: single DES has a 56-bit effective key and is brute-forceable;
// two-key 3DES is about 80 bits. Both are **for legacy data only** and
// MUST NOT be used for new protocols.

// desKind 区分 DES 家族的三种密钥形态。
//
// desKind distinguishes the three key shapes of the DES family.
type desKind int

const (
	// desSingle 表示单 DES（8 字节密钥，内部展开为 K‖K‖K 走 DES-EDE3）。
	//
	// desSingle is single DES (8-byte key, expanded to K‖K‖K internally
	// and run through DES-EDE3).
	desSingle desKind = iota
	// desEDE 表示 2 密钥 3DES（16 字节密钥）。
	//
	// desEDE is two-key 3DES (16-byte key).
	desEDE
	// desEDE3 表示 3 密钥 3DES（24 字节密钥）。
	//
	// desEDE3 is three-key 3DES (24-byte key).
	desEDE3
)

// desKeySizeOf 返回该 DES 形态的密钥长度。
//
// desKeySizeOf returns the key length of the DES variant.
func desKeySizeOf(kind desKind) int {
	switch kind {
	case desSingle:
		return DESKeySize
	case desEDE:
		return DESEDEKeySize
	case desEDE3:
		return DESEDE3KeySize
	}
	return 0
}

// desCipher 返回该 DES 形态在指定模式下的算法描述符。
// mode 取 "ecb" / "cbc"。单 DES 与 2 密钥 3DES 复用 DES-EDE3 描述符时，
// 密钥的展开/补齐由调用方负责（见 effectiveDESKey）。
//
// desCipher returns the descriptor of the DES variant for the given mode
// ("ecb" or "cbc"). When single DES or two-key 3DES reuses a DES-EDE3
// descriptor, the caller is responsible for key expansion (see
// effectiveDESKey).
func desCipher(kind desKind, mode string) *core.Cipher {
	switch kind {
	case desSingle, desEDE3:
		// 单 DES 走 3DES 描述符（K‖K‖K 等价）；三密钥 3DES 直接使用。
		switch mode {
		case "ecb":
			return core.DESEDE3ECB()
		case "cbc":
			return core.DESEDE3CBC()
		}
	case desEDE:
		switch mode {
		case "ecb":
			return core.DESEDEECB()
		case "cbc":
			return core.DESEDECBC()
		}
	}
	return nil
}

// effectiveDESKey 返回喂给底层描述符的密钥：单 DES 展开为 K‖K‖K。
// 其它形态原样返回。返回切片可能与入参共享底层数组，调用方不得就地修改。
//
// effectiveDESKey returns the key fed to the underlying descriptor:
// single DES is expanded to K‖K‖K, everything else passes through. The
// returned slice may share the caller's backing array; do not mutate it.
func effectiveDESKey(kind desKind, key []byte) []byte {
	if kind != desSingle || len(key) != DESKeySize {
		return key
	}
	out := make([]byte, DESEDE3KeySize)
	copy(out[0:DESKeySize], key)
	copy(out[DESKeySize:2*DESKeySize], key)
	copy(out[2*DESKeySize:], key)
	return out
}

// desCryptWithPad 按填充方式驱动一次 DES 家族加解密。
// kind 选形态，mode 选 "ecb"/"cbc"，pad 取 PaddingPKCS7 / PaddingZero /
// PaddingNone（空串等价于 PKCS#7）。密钥长度不符返回 ErrInvalidKeyLength，
// IV 长度不符或填充不合法返回对应错误。
//
// desCryptWithPad runs one DES-family encrypt/decrypt with the requested
// padding. kind selects the variant, mode is "ecb" or "cbc", and pad is
// PaddingPKCS7 / PaddingZero / PaddingNone (empty means PKCS#7). A wrong
// key length returns ErrInvalidKeyLength; a wrong IV length or an
// invalid padding returns the corresponding error.
func desCryptWithPad(key, iv, data []byte, enc bool, kind desKind, mode, pad string) ([]byte, error) {
	want := desKeySizeOf(kind)
	if len(key) != want {
		return nil, fmt.Errorf("sym: %s-%s: %w: key size %d, want %d",
			desNamePrefix(kind), mode, ErrInvalidKeyLength, len(key), want)
	}
	c := desCipher(kind, mode)
	if c == nil {
		return nil, fmt.Errorf("sym: %s: %w: mode %q", desNamePrefix(kind), ErrUnsupported, mode)
	}
	if mode == "cbc" && len(iv) != DESBlockSize {
		return nil, fmt.Errorf("sym: invalid iv size %d, want %d", len(iv), DESBlockSize)
	}
	if mode == "ecb" {
		iv = nil
	}
	return cryptPadded(c, effectiveDESKey(kind, key), iv, data, enc, pad, DESBlockSize)
}

// desNamePrefix 返回用于错误信息的算法名前缀。
//
// desNamePrefix returns the algorithm-name prefix used in error messages.
func desNamePrefix(kind desKind) string {
	switch kind {
	case desSingle:
		return "DES"
	case desEDE:
		return "DES-EDE"
	case desEDE3:
		return "DES-EDE3"
	}
	return "DES"
}

// desBlock 实现基于 DES-EDE3-ECB 的 cipher.Block（BlockSize 为 8）。
//
// desBlock implements cipher.Block on top of DES-EDE3-ECB (8-byte blocks).
type desBlock struct {
	encTpl *core.CipherCtx
	decTpl *core.CipherCtx
}

// NewDESCipher 返回单 DES 的 cipher.Block（无填充，BlockSize 为 8）。
// key 必须为 DESKeySize（8 字节）；内部以 K‖K‖K 驱动 DES-EDE3，输出与单 DES
// 完全一致。同一实例可被多个 goroutine 并发复用。
//
// 安全：单 DES 仅 56 位有效密钥，已可被穷举，**仅用于兼容既有数据**。
//
// NewDESCipher returns the single-DES cipher.Block (no padding, 8-byte
// blocks). key must be DESKeySize (8 bytes); internally it drives
// DES-EDE3 with K‖K‖K, producing output identical to single DES. The
// same instance is safe for concurrent use by multiple goroutines.
//
// Security: single DES has a 56-bit effective key and is brute-forceable;
// it exists **for legacy data only**.
func NewDESCipher(key []byte) (cipher.Block, error) {
	return newDESBlock(desSingle, key)
}

// newDESBlock 按 DES 形态构造 cipher.Block（无填充，BlockSize 为 8）。
// 单 DES 与 2 密钥 3DES 分别通过密钥展开与对应描述符实现。
//
// newDESBlock builds a padding-less cipher.Block (8-byte blocks) for the
// given DES variant, using key expansion and the matching descriptor.
func newDESBlock(kind desKind, key []byte) (cipher.Block, error) {
	want := desKeySizeOf(kind)
	if len(key) != want {
		return nil, fmt.Errorf("sym: %s: %w: key size %d, want %d",
			desNamePrefix(kind), ErrInvalidKeyLength, len(key), want)
	}
	eff := effectiveDESKey(kind, key)
	c := desCipher(kind, "ecb")
	if c == nil {
		return nil, fmt.Errorf("sym: %s: %w", desNamePrefix(kind), ErrUnsupported)
	}
	encTpl, err := newDESNoPadCtx(c, eff, true)
	if err != nil {
		return nil, err
	}
	decTpl, err := newDESNoPadCtx(c, eff, false)
	if err != nil {
		_ = encTpl.Close()
		return nil, err
	}
	return &desBlock{encTpl: encTpl, decTpl: decTpl}, nil
}

// BlockSize 返回 DES 分组长度（8）。
//
// BlockSize returns the DES block size (8).
func (b *desBlock) BlockSize() int { return DESBlockSize }

// Encrypt 加密单个分组。
//
// Encrypt encrypts a single 8-byte block from src into dst.
func (b *desBlock) Encrypt(dst, src []byte) {
	if len(src) < DESBlockSize {
		panic("sym: DES input not full block")
	}
	if len(dst) < DESBlockSize {
		panic("sym: DES output too short")
	}
	ctx, err := b.encTpl.Clone()
	if err != nil {
		panic(err)
	}
	defer ctx.Close()
	out, err := ctx.EncryptAll(src[:DESBlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst, out)
}

// Decrypt 解密单个分组。
//
// Decrypt decrypts a single 8-byte block from src into dst.
func (b *desBlock) Decrypt(dst, src []byte) {
	if len(src) < DESBlockSize {
		panic("sym: DES input not full block")
	}
	if len(dst) < DESBlockSize {
		panic("sym: DES output too short")
	}
	ctx, err := b.decTpl.Clone()
	if err != nil {
		panic(err)
	}
	defer ctx.Close()
	out, err := ctx.DecryptAll(src[:DESBlockSize])
	if err != nil {
		panic(err)
	}
	copy(dst, out)
}

// newDESNoPadCtx 创建无填充的 DES-EDE3-ECB 上下文（作为模板）。
//
// newDESNoPadCtx creates a no-padding DES-EDE3-ECB context (used as a
// template).
func newDESNoPadCtx(c *core.Cipher, key []byte, enc bool) (*core.CipherCtx, error) {
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

// EncryptDESECB 使用单 DES-ECB 加密（PKCS#7 填充）。
//
// 安全：单 DES 仅 56 位有效密钥，已可被穷举；ECB 无扩散语义。**仅用于兼容
// 既有数据**。实现上以 K‖K‖K 驱动 DES-EDE3，输出与单 DES 逐字节一致。
//
// EncryptDESECB encrypts with single DES-ECB (PKCS#7 padding).
//
// Security: single DES has a 56-bit effective key and is brute-forceable,
// and ECB has no diffusion. **For legacy data only.** Internally it drives
// DES-EDE3 with K‖K‖K, so the output is byte-identical to single DES.
func EncryptDESECB(key, data []byte) ([]byte, error) {
	return desCryptWithPad(key, nil, data, true, desSingle, "ecb", PaddingPKCS7)
}

// DecryptDESECB 使用单 DES-ECB 解密（PKCS#7 填充）。
//
// DecryptDESECB decrypts with single DES-ECB (PKCS#7 padding).
func DecryptDESECB(key, data []byte) ([]byte, error) {
	return desCryptWithPad(key, nil, data, false, desSingle, "ecb", PaddingPKCS7)
}

// EncryptDESCBC 使用单 DES-CBC 加密（PKCS#7 填充）。iv 必须为 DESBlockSize。
//
// 安全：单 DES 仅 56 位有效密钥，**仅用于兼容既有数据**。
//
// EncryptDESCBC encrypts with single DES-CBC (PKCS#7 padding).
// iv must be DESBlockSize bytes.
//
// Security: single DES has a 56-bit effective key; **for legacy data
// only**.
func EncryptDESCBC(key, iv, data []byte) ([]byte, error) {
	return desCryptWithPad(key, iv, data, true, desSingle, "cbc", PaddingPKCS7)
}

// DecryptDESCBC 使用单 DES-CBC 解密（PKCS#7 填充）。
//
// DecryptDESCBC decrypts with single DES-CBC (PKCS#7 padding).
func DecryptDESCBC(key, iv, data []byte) ([]byte, error) {
	return desCryptWithPad(key, iv, data, false, desSingle, "cbc", PaddingPKCS7)
}

// EncryptDESEDEECB 使用 2 密钥 3DES-ECB 加密（PKCS#7 填充）。
// key 必须为 DESEDEKeySize（16 字节）。
//
// 安全：2 密钥 3DES 有效强度约 80 位，仅用于兼容既有数据。
//
// EncryptDESEDEECB encrypts with two-key 3DES-ECB (PKCS#7 padding).
// key must be DESEDEKeySize (16 bytes).
//
// Security: two-key 3DES has roughly 80 bits of security and is for
// legacy data only.
func EncryptDESEDEECB(key, data []byte) ([]byte, error) {
	return desCryptWithPad(key, nil, data, true, desEDE, "ecb", PaddingPKCS7)
}

// DecryptDESEDEECB 使用 2 密钥 3DES-ECB 解密（PKCS#7 填充）。
//
// DecryptDESEDEECB decrypts with two-key 3DES-ECB (PKCS#7 padding).
func DecryptDESEDEECB(key, data []byte) ([]byte, error) {
	return desCryptWithPad(key, nil, data, false, desEDE, "ecb", PaddingPKCS7)
}

// EncryptDESEDECBC 使用 2 密钥 3DES-CBC 加密（PKCS#7 填充）。
// key 必须为 DESEDEKeySize，iv 必须为 DESBlockSize。
//
// EncryptDESEDECBC encrypts with two-key 3DES-CBC (PKCS#7 padding).
// key must be DESEDEKeySize and iv DESBlockSize bytes.
func EncryptDESEDECBC(key, iv, data []byte) ([]byte, error) {
	return desCryptWithPad(key, iv, data, true, desEDE, "cbc", PaddingPKCS7)
}

// DecryptDESEDECBC 使用 2 密钥 3DES-CBC 解密（PKCS#7 填充）。
//
// DecryptDESEDECBC decrypts with two-key 3DES-CBC (PKCS#7 padding).
func DecryptDESEDECBC(key, iv, data []byte) ([]byte, error) {
	return desCryptWithPad(key, iv, data, false, desEDE, "cbc", PaddingPKCS7)
}

// EncryptDESEDE3ECB 使用 3 密钥 3DES-ECB 加密（PKCS#7 填充）。
// key 必须为 DESEDE3KeySize（24 字节）。
//
// 安全：ECB 无扩散语义，不建议用于多块数据；3DES 正被 AES 取代，新协议请
// 优先选择 AES-GCM 或 SM4-GCM。
//
// EncryptDESEDE3ECB encrypts with three-key 3DES-ECB (PKCS#7 padding).
// key must be DESEDE3KeySize (24 bytes).
//
// Security: ECB has no diffusion and is not recommended for multi-block
// data; 3DES is being phased out in favour of AES, so new protocols should
// prefer AES-GCM or SM4-GCM.
func EncryptDESEDE3ECB(key, data []byte) ([]byte, error) {
	return desCryptWithPad(key, nil, data, true, desEDE3, "ecb", PaddingPKCS7)
}

// DecryptDESEDE3ECB 使用 3 密钥 3DES-ECB 解密（PKCS#7 填充）。
//
// DecryptDESEDE3ECB decrypts with three-key 3DES-ECB (PKCS#7 padding).
func DecryptDESEDE3ECB(key, data []byte) ([]byte, error) {
	return desCryptWithPad(key, nil, data, false, desEDE3, "ecb", PaddingPKCS7)
}

// EncryptDESEDE3CBC 使用 3 密钥 3DES-CBC 加密（PKCS#7 填充）。
// key 必须为 DESEDE3KeySize，iv 必须为 DESBlockSize。
//
// EncryptDESEDE3CBC encrypts with three-key 3DES-CBC (PKCS#7 padding).
// key must be DESEDE3KeySize and iv DESBlockSize bytes.
func EncryptDESEDE3CBC(key, iv, data []byte) ([]byte, error) {
	return desCryptWithPad(key, iv, data, true, desEDE3, "cbc", PaddingPKCS7)
}

// DecryptDESEDE3CBC 使用 3 密钥 3DES-CBC 解密（PKCS#7 填充）。
//
// DecryptDESEDE3CBC decrypts with three-key 3DES-CBC (PKCS#7 padding).
func DecryptDESEDE3CBC(key, iv, data []byte) ([]byte, error) {
	return desCryptWithPad(key, iv, data, false, desEDE3, "cbc", PaddingPKCS7)
}
