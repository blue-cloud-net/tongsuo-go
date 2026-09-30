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
	case HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512, HashSM3:
		return nil
	default:
		return fmt.Errorf("kdf: unsupported hash %q", md)
	}
}

// algos 是算法注册表；切片顺序即 Names() 的返回顺序（稳定）。
//
// algos is the algorithm registry; the slice order defines the stable
// order returned by Names().
var algos = []struct {
	name string
}{
	{"HKDF"},
	{"PBKDF2"},
}

// Names 返回本版支持的 KDF 算法名（顺序稳定：HKDF、PBKDF2）。
//
// Names returns the KDF algorithm names supported by this version in a
// stable order (HKDF, PBKDF2).
func Names() []string {
	out := make([]string, len(algos))
	for i, a := range algos {
		out[i] = a.name
	}
	return out
}

// lookup 按算法名查找；名称大小写不敏感。
//
// lookup resolves a KDF algorithm by name; matching is case-insensitive.
func lookup(name string) (string, error) {
	key := strings.ToUpper(strings.TrimSpace(name))
	for _, a := range algos {
		if a.name == key {
			return a.name, nil
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
	// Length 是派生输出字节长度（HKDF / PBKDF2 / Argon2ID 必填且 > 0）。
	//
	// Length is the derived output length in bytes.
	Length int
	// TimeCost / Memory / Threads 是 Argon2ID 的成本参数。
	//
	// TimeCost / Memory / Threads are Argon2ID cost parameters.
	TimeCost uint32
	Memory   uint32
	Threads  uint32
}

// Derive 按算法名一次性派生；未知算法名返回 ErrUnknownAlgorithm。
// 字段语义以 Options 注释为准。Argon2ID 当前未接线（Tongsuo 未编译 provider
// 或尚未实现），仍返回 ErrUnsupported。
//
// Derive performs a one-shot derivation by algorithm name; unknown
// names return ErrUnknownAlgorithm. See the Options comments for
// per-field semantics. Argon2ID currently returns ErrUnsupported —
// either the Tongsuo build lacks the provider or the binding is not
// yet wired.
func Derive(name string, opts *Options) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("kdf: nil Options")
	}
	alg, err := lookup(name)
	if err != nil {
		return nil, err
	}
	switch alg {
	case "HKDF":
		if opts.Length <= 0 {
			return nil, fmt.Errorf("kdf: HKDF: Length must be > 0")
		}
		return HKDF(opts.Digest, opts.Secret, opts.Salt, opts.Info, opts.Length)
	case "PBKDF2":
		if opts.Iterations < 1 {
			return nil, fmt.Errorf("kdf: PBKDF2: Iterations must be >= 1")
		}
		if opts.Length <= 0 {
			return nil, fmt.Errorf("kdf: PBKDF2: Length must be > 0")
		}
		return PBKDF2(opts.Digest, opts.Password, opts.Salt, opts.Iterations, opts.Length)
	}
	return nil, fmt.Errorf("kdf: %q: %w", name, ErrUnsupported)
}
