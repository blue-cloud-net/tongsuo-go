package kdf

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Hash 标识 KDF 可用的消息摘要算法。
//
// Hash identifies a message-digest algorithm usable with the KDF helpers.
type Hash string

// KDF 支持的摘要算法。
//
// Message-digest algorithms supported by the KDF helpers.
const (
	// HashMD5 标识 MD5（仅用于兼容旧协议，勿用于安全用途）。
	//
	// HashMD5 identifies MD5 (legacy compatibility only, not for security).
	HashMD5 Hash = "MD5"
	// HashSHA1 标识 SHA-1。
	//
	// HashSHA1 identifies SHA-1.
	HashSHA1 Hash = "SHA1"
	// HashSHA224 标识 SHA-224。
	//
	// HashSHA224 identifies SHA-224.
	HashSHA224 Hash = "SHA224"
	// HashSHA256 标识 SHA-256。
	//
	// HashSHA256 identifies SHA-256.
	HashSHA256 Hash = "SHA256"
	// HashSHA384 标识 SHA-384。
	//
	// HashSHA384 identifies SHA-384.
	HashSHA384 Hash = "SHA384"
	// HashSHA512 标识 SHA-512。
	//
	// HashSHA512 identifies SHA-512.
	HashSHA512 Hash = "SHA512"
	// HashSM3 标识 SM3（GB/T 32905）。
	//
	// HashSM3 identifies SM3 (GB/T 32905).
	HashSM3 Hash = "SM3"
	// HashMD5SHA1 标识 MD5-SHA1 组合摘要，仅用于 TLS1PRF（TLS 1.0/1.1 PRF
	// 的默认选择）；不得用于一般摘要场景。
	//
	// HashMD5SHA1 identifies the combined MD5-SHA1 digest used only by
	// TLS1PRF (the default for the TLS 1.0/1.1 PRF); do not use it for
	// general digestion.
	HashMD5SHA1 Hash = "MD5-SHA1"
)

// ErrUnknownAlgorithm 表示按名分发时传入的名称不在 Names() 内。
// 按名入口返回的错误均可用 errors.Is(err, ErrUnknownAlgorithm) 判定。
//
// ErrUnknownAlgorithm reports that a by-name entry was given a name not
// present in Names(). Errors from the by-name entries can be tested with
// errors.Is(err, ErrUnknownAlgorithm).
var ErrUnknownAlgorithm = errors.New("kdf: unknown algorithm")

// ErrUnsupported 表示请求的算法或特性在当前 Tongsuo 构建中不可用
// （典型如 Argon2id 未编译 provider）。可与 errors.Is 配合判定。
//
// ErrUnsupported reports that the requested algorithm or feature is not
// available in the current Tongsuo build (typical example: Argon2id
// without its provider compiled in).
var ErrUnsupported = errors.New("kdf: unsupported")

// HKDF 使用 HKDF（RFC 5869，extract-and-expand）从 secret 派生 length 字节。
// md 为摘要算法；secret 不能为空；salt/info 可为空。失败返回包装 OpError 的
// 错误。
//
// HKDF derives length bytes from secret using HKDF (RFC 5869,
// extract-and-expand). md selects the digest; secret must be non-empty;
// salt and info may be empty. On failure it returns an error wrapping
// an OpError.
func HKDF(md Hash, secret, salt, info []byte, length int) ([]byte, error) {
	if err := validateHash(md); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("kdf: empty HKDF secret")
	}
	if length <= 0 {
		return nil, fmt.Errorf("kdf: invalid output length %d", length)
	}
	return core.HKDF(string(md), secret, salt, info, length)
}

// PBKDF2 使用 PBKDF2（RFC 8018）从口令派生 keyLen 字节。
// md 为摘要算法；iter 为迭代次数（>=1）；password 不能为空。失败返回包装
// OpError 的错误。
//
// PBKDF2 derives keyLen bytes from a password using PBKDF2 (RFC 8018).
// md selects the digest; iter is the iteration count (>= 1); password
// must be non-empty. On failure it returns an error wrapping an OpError.
func PBKDF2(md Hash, password, salt []byte, iter, keyLen int) ([]byte, error) {
	if err := validateHash(md); err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("kdf: empty password")
	}
	if iter < 1 {
		return nil, fmt.Errorf("kdf: invalid iteration count %d", iter)
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("kdf: invalid key length %d", keyLen)
	}
	return core.PBKDF2(string(md), password, salt, iter, keyLen)
}

// Argon2ID 使用 Argon2id 从口令派生 keyLen 字节。
// timeCost/memory 为时间与内存成本参数（memory 单位 KiB），threads 为并行度。
// 当前 Tongsuo 构建通常不含 ARGON2ID KDF provider，此时返回包装 ErrUnsupported
// 的错误；待 provider 可用后接线实现派生。
//
// Argon2ID derives keyLen bytes from a password using Argon2id.
// timeCost and memory are the time and memory cost parameters (memory
// in KiB) and threads is the parallelism. The current Tongsuo build
// usually lacks the ARGON2ID KDF provider, in which case an error
// wrapping ErrUnsupported is returned; the derivation will be wired
// once the provider is available.
func Argon2ID(password, salt []byte, timeCost, memory, threads uint32, keyLen int) ([]byte, error) {
	if !core.Argon2IDAvailable() {
		return nil, fmt.Errorf("%w: ARGON2ID KDF provider not available in this Tongsuo build", ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: ARGON2ID derivation not yet wired", ErrUnsupported)
}

// Argon2IDAvailable 报告当前 Tongsuo 构建是否提供 ARGON2ID KDF。
//
// Argon2IDAvailable reports whether the current Tongsuo build provides
// the ARGON2ID KDF. Argon2id requires OpenSSL 3.2+ with the provider
// compiled in; the current build usually does not provide it.
func Argon2IDAvailable() bool { return core.Argon2IDAvailable() }

// validateHash 校验 md 是否为受支持的摘要算法。
//
// validateHash reports whether md is a supported digest algorithm.
func validateHash(md Hash) error {
	switch md {
	case HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512, HashSM3,
		HashMD5SHA1:
		return nil
	default:
		return fmt.Errorf("kdf: unsupported hash %q", md)
	}
}

// algos 是算法注册表；切片顺序即 Names() 的返回顺序（稳定）。
// provider 是传给自己 native 层的算法名（X942KDF 在 provider 侧规范名为
// "X942KDF-ASN1"）。
//
// algos is the algorithm registry; the slice order defines the stable
// order returned by Names(). provider is the name handed to the native
// layer (the provider canonical name for X942KDF is "X942KDF-ASN1").
var algos = []struct {
	name     string
	provider string
}{
	{"HKDF", "HKDF"},
	{"PBKDF2", "PBKDF2"},
	{"SCRYPT", "SCRYPT"},
	{"SSKDF", "SSKDF"},
	{"TLS1-PRF", "TLS1-PRF"},
	{"TLS13-KDF", "TLS13-KDF"},
	{"KBKDF", "KBKDF"},
	{"X942KDF", "X942KDF-ASN1"},
	{"X963KDF", "X963KDF"},
	{"HMAC-DRBG-KDF", "HMAC-DRBG-KDF"},
}

// Names 返回本版支持的 KDF 算法名（顺序稳定：HKDF、PBKDF2、SCRYPT、
// SSKDF、TLS1-PRF、TLS13-KDF、KBKDF、X942KDF、X963KDF、HMAC-DRBG-KDF）。
//
// Names returns the KDF algorithm names supported by this version in a
// stable order (HKDF, PBKDF2, SCRYPT, SSKDF, TLS1-PRF, TLS13-KDF, KBKDF,
// X942KDF, X963KDF, HMAC-DRBG-KDF).
func Names() []string {
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = a.name
	}
	return out
}

// lookup 按算法名查找；名称大小写不敏感，返回 provider 侧算法名。
//
// lookup resolves a KDF algorithm by name (case-insensitively) and
// returns the provider-side algorithm name.
func lookup(name string) (string, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	for _, a := range algos {
		if a.name == key {
			return a.provider, nil
		}
	}
	return "", fmt.Errorf("kdf: %q: %w", name, ErrUnknownAlgorithm)
}

// Options 是按名 Derive 入口的参数包。
// 各字段对应不同算法的子集；未涉及字段被忽略。
// Digest/Length/Iterations 等必填字段留零值时 Derive 会拒绝并返回错误。
//
// Options carries by-name Derive parameters. Each algorithm uses a
// subset of the fields; unspecified fields are ignored. Required
// fields (Digest / Length / Iterations / etc.) that are left zero cause
// Derive to reject the call with an error.
type Options struct {
	// Digest 是摘要算法（HKDF / PBKDF2 必填；Argon2ID 忽略）。
	//
	// Digest selects the message-digest (required for HKDF / PBKDF2).
	Digest Hash
	// Secret 是 HKDF 的输入密钥材料（HKDF 必填且非空）。
	//
	// Secret is the HKDF input keying material.
	Secret []byte
	// Salt 是 HKDF / PBKDF2 的盐（均可空）。
	//
	// Salt is the salt for HKDF / PBKDF2.
	Salt []byte
	// Info 是 HKDF 的 context 字节（HKDF 专用，可空）。
	//
	// Info is the HKDF context info.
	Info []byte
	// Password 是 PBKDF2 / Argon2ID 的口令。
	//
	// Password is the password for PBKDF2 / Argon2ID.
	Password []byte
	// Iterations 是 PBKDF2 的迭代次数（PBKDF2 必填且 >= 1）。
	//
	// Iterations is the PBKDF2 iteration count.
	Iterations int
	// Length 是派生输出字节长度（全部算法必填且 > 0）。
	//
	// Length is the derived output length in bytes (required by every
	// algorithm and must be > 0).
	Length int
	// Mode 是模式字符串：HKDF / TLS13-KDF 取 "EXTRACT_ONLY" / "EXPAND_ONLY"
	// （TLS13-KDF 无默认值，必须显式指定）；KBKDF 取 "COUNTER" / "FEEDBACK"
	// （默认 "COUNTER"）。其余算法忽略。
	//
	// Mode is the mode string: HKDF / TLS13-KDF take "EXTRACT_ONLY" or
	// "EXPAND_ONLY" (TLS13-KDF has no default and must specify it);
	// KBKDF takes "COUNTER" or "FEEDBACK" (default "COUNTER").
	// Other algorithms ignore it.
	Mode string
	// Label / Prefix / Data 是 TLS13-KDF 的标签、标签前缀与上下文字节；
	// Prefix 的标准值为 "tls13 "（含尾部空格）。
	//
	// Label / Prefix / Data are the TLS13-KDF label, label prefix and
	// context bytes; the standard Prefix value is "tls13 " (with the
	// trailing space).
	Label  []byte
	Prefix []byte
	Data   []byte
	// Seed 是 TLS1-PRF 的种子（TLS1-PRF 必填）。
	//
	// Seed is the TLS1-PRF seed (required by TLS1-PRF).
	Seed []byte
	// UKM 是 X942KDF 的用户密钥材料（可空）。
	//
	// UKM is the X942KDF user keying material (optional).
	UKM []byte
	// CEKAlg 是 X942KDF 的目标 CEK 算法名（必填，如 "AES-128-WRAP"）。
	//
	// CEKAlg names the X942KDF target content-encryption key algorithm
	// (required, for example "AES-128-WRAP").
	CEKAlg string
	// MAC 是 KBKDF 的底层 MAC 名（必填，如 "HMAC" / "CMAC" / "KMAC-128"）。
	//
	// MAC names the KBKDF underlying MAC (required, for example "HMAC",
	// "CMAC" or "KMAC-128").
	MAC string
	// Entropy / Nonce 是 HMAC-DRBG-KDF 的熵输入与 nonce（Entropy 必填）。
	//
	// Entropy / Nonce are the HMAC-DRBG-KDF entropy input and nonce
	// (Entropy is required).
	Entropy []byte
	Nonce   []byte
	// N / R / P 是 scrypt 的 CPU/内存成本参数（三者均必填）；
	// KBKDF 借用 R 作为计数器宽度上限。
	//
	// N / R / P are the scrypt cost parameters (all three required);
	// KBKDF reuses R as the counter width limit.
	N uint64
	R uint64
	P uint64
	// MaxMem 是 scrypt 的内存上限（字节）。
	//
	// MaxMem is the scrypt memory limit in bytes.
	MaxMem uint64
	// UseL 在输出末尾附加密钥比特长度。注意本字段总会被下传：false 表示
	// 显式传 use-l=0，而 CLI 与部分上游用例的默认值是 1（故与 CLI 对拍时
	// 需显式传 -kdfopt use-l:0）。
	//
	// UseL appends the key length in bits to the output. The field is
	// always forwarded: false means an explicit use-l=0, whereas the CLI
	// default is 1 (a CLI parity test must therefore pass
	// -kdfopt use-l:0 explicitly).
	UseL bool
	// UseSeparator 选择 KBKDF 的 separator 变体。与 UseL 一样总会下传：
	// false 表示显式传 use-separator=0，而 provider 默认值为 1。
	//
	// UseSeparator selects the separator variant of KBKDF. Like UseL it is
	// always forwarded: false means an explicit use-separator=0, whereas
	// the provider default is 1.
	UseSeparator bool
	// UseKeyBits 为 true 时显式下传 X942KDF 的 use-keybits 参数
	// （以密钥比特长度替代 supp-pubinfo）；false 表示不下传，由 provider 取
	// 默认值（默认即为启用）。本库当前不提供显式关闭入口。
	//
	// UseKeyBits forwards the X942KDF use-keybits parameter explicitly when
	// true (the key length in bits replaces supp-pubinfo). A false value
	// omits the parameter so the provider default applies (which is
	// "enabled"). There is currently no way to turn it off explicitly.
	UseKeyBits bool
	// TimeCost / Memory / Threads 是 Argon2ID 的成本参数。
	//
	// TimeCost / Memory / Threads are Argon2ID cost parameters.
	TimeCost uint32
	Memory   uint32
	Threads  uint32
}

// Derive 按算法名一次性派生；未知算法名返回 ErrUnknownAlgorithm。
// 字段语义以 Options 注释为准。Argon2ID 不在 Names() 内，需直接调用
// Argon2ID；当前 Tongsuo 构建通常未编译其 provider，那时返回 ErrUnsupported。
//
// Derive performs a one-shot derivation by algorithm name; unknown
// names return ErrUnknownAlgorithm. See the Options comments for
// per-field semantics. Argon2ID is not part of Names(); call Argon2ID
// directly. Most Tongsuo builds do not compile its provider and return
// ErrUnsupported.
func Derive(name string, opts *Options) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("kdf: nil Options")
	}
	alg, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if opts.Length <= 0 {
		return nil, fmt.Errorf("kdf: %s: Length must be > 0", name)
	}
	params, err := buildParams(alg, name, opts)
	if err != nil {
		return nil, err
	}
	out := make([]byte, opts.Length)
	if err := core.Derive(alg, params, out); err != nil {
		return nil, fmt.Errorf("kdf: %s: %w", name, err)
	}
	return out, nil
}

// buildParams 校验算法必填字段并组装底层参数包。
// 校验失败返回带算法名的明确错误，保证上层不必猜测缺了什么。
//
// buildParams validates the required fields of alg and assembles the
// native parameter struct. Validation failures return a named error so
// callers need not guess which field is missing.
func buildParams(alg, name string, o *Options) (*core.KDFParams, error) {
	p := &core.KDFParams{
		Digest:       string(o.Digest),
		Secret:       o.Secret,
		Salt:         o.Salt,
		Info:         o.Info,
		Pass:         o.Password,
		Seed:         o.Seed,
		Label:        o.Label,
		Prefix:       o.Prefix,
		Data:         o.Data,
		UKM:          o.UKM,
		Entropy:      o.Entropy,
		Nonce:        o.Nonce,
		Iter:         uint64(o.Iterations),
		N:            o.N,
		R:            o.R,
		P:            o.P,
		MaxMem:       o.MaxMem,
		CEKAlg:       o.CEKAlg,
		MAC:          o.MAC,
		Mode:         strings.ToUpper(strings.TrimSpace(o.Mode)),
		UseL:         o.UseL,
		UseSeparator: o.UseSeparator,
		UseKeyBits:   o.UseKeyBits,
	}
	// HKDF / TLS13-KDF / KBKDF 的密钥材料参数名是 "key"；SSKDF / TLS1-PRF /
	// X942KDF / X963KDF 用 "secret"。两者同时设置会触发 provider 的参数
	// 互斥校验，因此按算法选择。
	//
	// HKDF / TLS13-KDF / KBKDF name their keying material "key", whereas
	// SSKDF / TLS1-PRF / X942KDF / X963KDF use "secret". Setting both trips
	// the provider's mutual-exclusion check, so the field is chosen per
	// algorithm.
	switch alg {
	case "HKDF", "TLS13-KDF", "KBKDF":
		p.Key = o.Secret
	}

	requireDigest := func() error {
		if err := validateHash(o.Digest); err != nil {
			return fmt.Errorf("kdf: %s: %w", name, err)
		}
		return nil
	}

	switch alg {
	case "HKDF", "TLS1-PRF", "TLS13-KDF", "X942KDF-ASN1",
		"X963KDF", "HMAC-DRBG-KDF", "SSKDF":
		if err := requireDigest(); err != nil {
			return nil, err
		}
	case "PBKDF2":
		if err := requireDigest(); err != nil {
			return nil, err
		}
		if o.Iterations < 1 {
			return nil, fmt.Errorf("kdf: %s: Iterations must be >= 1", name)
		}
	}

	switch alg {
	case "HKDF":
		if len(o.Secret) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret must not be empty", name)
		}
	case "PBKDF2":
		if len(o.Password) == 0 {
			return nil, fmt.Errorf("kdf: %s: Password must not be empty", name)
		}
	case "SCRYPT":
		if len(o.Password) == 0 {
			return nil, fmt.Errorf("kdf: %s: Password must not be empty", name)
		}
		if len(o.Salt) == 0 {
			return nil, fmt.Errorf("kdf: %s: Salt must not be empty", name)
		}
		if o.N < 2 || o.R < 1 || o.P < 1 {
			return nil, fmt.Errorf("kdf: %s: N must be >= 2 and R, P must be >= 1", name)
		}
	case "SSKDF":
		if len(o.Secret) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret must not be empty", name)
		}
	case "TLS1-PRF":
		if len(o.Secret) == 0 || len(o.Seed) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret and Seed must not be empty", name)
		}
	case "TLS13-KDF":
		if p.Mode != "EXTRACT_ONLY" && p.Mode != "EXPAND_ONLY" {
			return nil, fmt.Errorf("kdf: %s: Mode must be EXTRACT_ONLY or EXPAND_ONLY", name)
		}
		if len(o.Secret) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret must not be empty", name)
		}
	case "KBKDF":
		if len(o.Secret) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret must not be empty", name)
		}
		if o.MAC == "" {
			return nil, fmt.Errorf("kdf: %s: MAC must not be empty", name)
		}
		// HMAC / KMAC 需要摘要；CMAC 需要的是分组算法（cipher），
		// 但本库的 KBKDF 通道不暴露 cipher 参数，故只对 HMAC / KMAC 校验摘要。
		//
		// HMAC / KMAC need a digest; CMAC needs a block cipher instead,
		// which this KBKDF path does not expose, so the digest is only
		// required for HMAC / KMAC.
		if strings.HasPrefix(strings.ToUpper(o.MAC), "HMAC") ||
			strings.HasPrefix(strings.ToUpper(o.MAC), "KMAC") {
			if err := requireDigest(); err != nil {
				return nil, err
			}
		}
		if p.Mode == "" {
			p.Mode = "COUNTER"
		}
		if p.Mode != "COUNTER" && p.Mode != "FEEDBACK" {
			return nil, fmt.Errorf("kdf: %s: Mode must be COUNTER or FEEDBACK", name)
		}
		if o.R == 0 {
			p.R = 32
		}
	case "X942KDF-ASN1":
		if len(o.Secret) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret must not be empty", name)
		}
		if o.CEKAlg == "" {
			return nil, fmt.Errorf("kdf: %s: CEKAlg must not be empty", name)
		}
	case "X963KDF":
		if len(o.Secret) == 0 {
			return nil, fmt.Errorf("kdf: %s: Secret must not be empty", name)
		}
	case "HMAC-DRBG-KDF":
		if len(o.Entropy) == 0 {
			return nil, fmt.Errorf("kdf: %s: Entropy must not be empty", name)
		}
	}
	return p, nil
}
