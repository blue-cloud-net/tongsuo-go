package kdf

import "fmt"

// Scrypt 使用 scrypt（RFC 7914）从口令派生 keyLen 字节。
// n 为 CPU/内存成本（必须是 2 的幂且 > 1），r 为块大小，p 为并行度，
// maxMem 为内存上限（字节，0 表示由 provider 取默认）。password 与 salt 不能为空。
// 失败返回包装 OpError 的错误。
//
// Scrypt derives keyLen bytes from a password using scrypt (RFC 7914).
// n is the CPU/memory cost (a power of two greater than 1), r is the block
// size, p is the parallelism and maxMem is the memory limit in bytes (0
// lets the provider pick its default). password and salt must be
// non-empty. On failure it returns an error wrapping an OpError.
func Scrypt(password, salt []byte, n, r, p uint32, maxMem, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("kdf: empty password")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("kdf: empty salt")
	}
	if n < 2 || r < 1 || p < 1 {
		return nil, fmt.Errorf("kdf: invalid scrypt cost n=%d r=%d p=%d", n, r, p)
	}
	if maxMem < 0 {
		return nil, fmt.Errorf("kdf: invalid scrypt maxMem %d", maxMem)
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("kdf: invalid key length %d", keyLen)
	}
	return Derive("SCRYPT", &Options{
		Password: password,
		Salt:     salt,
		N:        uint64(n),
		R:        uint64(r),
		P:        uint64(p),
		MaxMem:   uint64(maxMem),
		Length:   keyLen,
	})
}

// SSKDF 使用单步 KDF（SP 800-56C / ANSI X9.63 家族）从共享秘密派生 length 字节。
// md 为摘要算法；secret 不能为空；salt/info 可为空。失败返回包装 OpError 的错误。
//
// SSKDF derives length bytes from a shared secret using the single-step
// KDF family (SP 800-56C / ANSI X9.63). md selects the digest; secret must
// be non-empty; salt and info may be empty. On failure it returns an error
// wrapping an OpError.
func SSKDF(md Hash, secret, salt, info []byte, length int) ([]byte, error) {
	return Derive("SSKDF", &Options{
		Digest: md,
		Secret: secret,
		Salt:   salt,
		Info:   info,
		Length: length,
	})
}

// TLS1PRF 使用 TLS 1.0/1.1 PRF（RFC 2246）从 secret 与 seed 派生 length 字节。
// md 通常取 HashMD5SHA1（TLS 1.0/1.1 的标准选择）；secret 与 seed 不能为空。
// 失败返回包装 OpError 的错误。
//
// TLS1PRF derives length bytes from secret and seed using the TLS 1.0/1.1
// PRF (RFC 2246). md is usually HashMD5SHA1 (the standard TLS 1.0/1.1
// choice); secret and seed must be non-empty. On failure it returns an
// error wrapping an OpError.
func TLS1PRF(md Hash, secret, seed []byte, length int) ([]byte, error) {
	return Derive("TLS1-PRF", &Options{
		Digest: md,
		Secret: secret,
		Seed:   seed,
		Length: length,
	})
}

// TLS13KDFExtract 执行 TLS 1.3 的 HKDF-Extract 步（RFC 8446 §7.1）。
// md 为摘要算法；secret 为输入密钥材料；salt 可为空。
// 失败返回包装 OpError 的错误。
//
// TLS13KDFExtract performs the TLS 1.3 HKDF-Extract step (RFC 8446
// §7.1). md selects the digest; secret is the input keying material; salt
// may be empty. On failure it returns an error wrapping an OpError.
func TLS13KDFExtract(md Hash, secret, salt []byte) ([]byte, error) {
	return Derive("TLS13-KDF", &Options{
		Digest: md,
		Mode:   "EXTRACT_ONLY",
		Secret: secret,
		Salt:   salt,
		Length: digestSize(md),
	})
}

// TLS13KDFExpand 执行 TLS 1.3 的 HKDF-Expand-Label 步（RFC 8446 §7.1）。
// secret 为 Extract 步的输出；label 形如 "c e traffic"；context 为握手
// transcript 摘要（可空）。输出长度由 length 指定。
// 失败返回包装 OpError 的错误。
//
// TLS13KDFExpand performs the TLS 1.3 HKDF-Expand-Label step (RFC 8446
// §7.1). secret is the output of the extract step; label looks like
// "c e traffic"; context is the handshake transcript digest (may be
// empty). length sets the output size. On failure it returns an error
// wrapping an OpError.
func TLS13KDFExpand(md Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	return Derive("TLS13-KDF", &Options{
		Digest: md,
		Mode:   "EXPAND_ONLY",
		Secret: secret,
		Label:  []byte(label),
		Prefix: []byte("tls13 "),
		Data:   context,
		Length: length,
	})
}

// X963KDF 使用 ANSI X9.63 KDF（SHA-1/SHA-2 系列）从共享秘密派生 length 字节。
// md 为摘要算法；secret 不能为空；info 可为空。失败返回包装 OpError 的错误。
//
// X963KDF derives length bytes from a shared secret using the ANSI X9.63
// KDF. md selects the digest; secret must be non-empty; info may be
// empty. On failure it returns an error wrapping an OpError.
func X963KDF(md Hash, secret, info []byte, length int) ([]byte, error) {
	return Derive("X963KDF", &Options{
		Digest: md,
		Secret: secret,
		Info:   info,
		Length: length,
	})
}

// X942KDF 使用 ANSI X9.42 KDF（RFC 2631）从共享秘密派生 CEK。
// md 为摘要算法；secret 不能为空；ukm 为用户密钥材料（可空）；
// cekAlg 为目标 CEK 算法名（如 "id-aes128-wrap"，必填）；
// useKeyBits 为真时显式下传 use-keybits（provider 默认已启用，故一般传 false）。
// 失败返回包装 OpError 的错误。
//
// X942KDF derives a content-encryption key from a shared secret using the
// ANSI X9.42 KDF (RFC 2631). md selects the digest; secret must be
// non-empty; ukm is the optional user keying material; cekAlg names the
// target CEK algorithm (for example "id-aes128-wrap", required);
// useKeyBits replaces supp-pubinfo with the key length in bits.
// On failure it returns an error wrapping an OpError.
func X942KDF(md Hash, secret, ukm []byte, cekAlg string, useKeyBits bool, length int) ([]byte, error) {
	return Derive("X942KDF", &Options{
		Digest:     md,
		Secret:     secret,
		UKM:        ukm,
		CEKAlg:     cekAlg,
		UseKeyBits: useKeyBits,
		Length:     length,
	})
}

// KBKDFOptions 是 KBKDF（SP 800-108）的参数包。
// MAC 与 Secret 必填；Mode 取 "COUNTER"（默认）或 "FEEDBACK"。
//
// KBKDFOptions carries the KBKDF (SP 800-108) parameters. MAC and Secret
// are required; Mode is "COUNTER" (the default) or "FEEDBACK".
type KBKDFOptions struct {
	// Digest 是底层 MAC 使用的摘要算法（HMAC / KMAC 必填）。
	//
	// Digest is the digest used by the underlying MAC (required for
	// HMAC / KMAC).
	Digest Hash
	// MAC 是底层 MAC 实现名（必填），如 "HMAC"、"CMAC"、"KMAC-128"。
	//
	// MAC names the underlying MAC implementation (required), for
	// example "HMAC", "CMAC" or "KMAC-128".
	MAC string
	// Mode 取 "COUNTER" / "FEEDBACK"；留空等价于 "COUNTER"。
	//
	// Mode is "COUNTER" or "FEEDBACK"; empty means "COUNTER".
	Mode string
	// Secret 是密钥材料（必填）。
	//
	// Secret is the keying material (required).
	Secret []byte
	// Label 作为固定输入（provider 侧 salt 参数）。
	//
	// Label is the fixed input (the provider-side salt parameter).
	Label []byte
	// Context 是上下文字节。
	//
	// Context is the context bytes.
	Context []byte
	// R 是计数器宽度上限（比特）；留空（0）取 32。
	//
	// R is the counter width limit in bits; 0 means 32.
	R int
	// UseL 在输出末尾附加密钥比特长度。
	//
	// UseL appends the key length in bits to the output.
	UseL bool
	// UseSeparator 选择 separator 变体。
	//
	// UseSeparator selects the separator variant.
	UseSeparator bool
}

// KBKDF 使用 SP 800-108 KBKDF 派生 length 字节。
// opts 为 nil 或缺少必填字段时返回错误；失败时返回包装 OpError 的错误。
//
// KBKDF derives length bytes using the SP 800-108 KBKDF. A nil opts or a
// missing required field yields an error; failures wrap an OpError.
func KBKDF(opts *KBKDFOptions, length int) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("kdf: nil KBKDFOptions")
	}
	if opts.MAC == "" {
		return nil, fmt.Errorf("kdf: KBKDF: MAC must not be empty")
	}
	if len(opts.Secret) == 0 {
		return nil, fmt.Errorf("kdf: KBKDF: Secret must not be empty")
	}
	r := opts.R
	if r <= 0 {
		r = 32
	}
	return Derive("KBKDF", &Options{
		Digest:       opts.Digest,
		Mode:         opts.Mode,
		MAC:          opts.MAC,
		Secret:       opts.Secret,
		Salt:         opts.Label,
		Info:         opts.Context,
		R:            uint64(r),
		UseL:         opts.UseL,
		UseSeparator: opts.UseSeparator,
		Length:       length,
	})
}

// HMACDRBG 使用 HMAC-DRBG（SP 800-90A）从 entropy 与 nonce 派生 length 字节。
// md 为摘要算法；entropy 不能为空；nonce 可为空。
// 同一组输入会得到相同输出，故不宜用于需要不可预测性的场景。
// 失败返回包装 OpError 的错误。
//
// HMACDRBG derives length bytes from entropy and nonce using HMAC-DRBG
// (SP 800-90A). md selects the digest; entropy must be non-empty; nonce
// may be empty. Identical inputs yield identical outputs, so do not use
// this for unpredictable-byte generation. On failure it returns an error
// wrapping an OpError.
func HMACDRBG(md Hash, entropy, nonce []byte, length int) ([]byte, error) {
	return Derive("HMAC-DRBG-KDF", &Options{
		Digest:  md,
		Entropy: entropy,
		Nonce:   nonce,
		Length:  length,
	})
}

// digestSize 返回 md 的输出字节数；未知算法返回 0。
// 仅用于 TLS13KDFExtract 推导输出长度（Extract 步输出等于摘要长度）。
//
// digestSize returns the output size of md in bytes, or 0 for an unknown
// algorithm. It is used by TLS13KDFExtract, whose output length equals
// the digest length.
func digestSize(md Hash) int {
	switch md {
	case HashMD5:
		return 16
	case HashSHA1:
		return 20
	case HashSHA224:
		return 28
	case HashSHA256, HashSM3:
		return 32
	case HashSHA384:
		return 48
	case HashSHA512:
		return 64
	default:
		return 0
	}
}
