package key

import (
	"fmt"

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
	// HashMD5 标识 MD5（仅用于兼容旧协议,勿用于安全用途）。
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

// HKDF 使用 HKDF（RFC 5869，extract-and-expand）从 secret 派生 length 字节。
// md 为摘要算法；secret 不能为空；salt/info 可为空。派生结果通常用于对称密钥
// 材料：长度为 16/32 时可用 NewAESKey 包装为 AES-128/256，长度 16 亦可用
// NewSM4Key 包装为 SM4。失败返回包装 OpError 的错误。
//
// HKDF derives length bytes from secret using HKDF (RFC 5869,
// extract-and-expand). md selects the digest; secret must be non-empty; salt
// and info may be empty. The derived bytes are typically used as symmetric
// key material: wrap a 16/32-byte result with NewAESKey for AES-128/256, or
// a 16-byte result with NewSM4Key for SM4. On failure it returns an error
// wrapping an OpError.
func HKDF(md Hash, secret, salt, info []byte, length int) ([]byte, error) {
	if err := validateHash(md); err != nil {
		return nil, err
	}
	return core.HKDF(string(md), secret, salt, info, length)
}

// PBKDF2 使用 PBKDF2（RFC 8018）从口令派生 keyLen 字节。
// md 为摘要算法；iter 为迭代次数（>=1）；password 不能为空。失败返回包装
// OpError 的错误。
//
// PBKDF2 derives keyLen bytes from a password using PBKDF2 (RFC 8018).
// md selects the digest; iter is the iteration count (>= 1); password must be
// non-empty. On failure it returns an error wrapping an OpError.
func PBKDF2(md Hash, password, salt []byte, iter, keyLen int) ([]byte, error) {
	if err := validateHash(md); err != nil {
		return nil, err
	}
	return core.PBKDF2(string(md), password, salt, iter, keyLen)
}

// Argon2ID 使用 Argon2id 从口令派生 keyLen 字节。
// timeCost/memory 为时间与内存成本参数（KiB），threads 为并行度。当前 Tongsuo
// 构建通常不含 ARGON2ID KDF provider，此时返回包装 ErrUnsupported 的错误；
// 待 provider 可用后接线实现派生。
//
// Argon2ID derives keyLen bytes from a password using Argon2id.
// timeCost and memory are the time and memory cost parameters (memory in
// KiB) and threads is the parallelism. The current Tongsuo build usually
// lacks the ARGON2ID KDF provider, in which case an error wrapping
// ErrUnsupported is returned; the derivation will be wired once the
// provider is available.
func Argon2ID(password, salt []byte, timeCost, memory, threads uint32, keyLen int) ([]byte, error) {
	if !core.Argon2IDAvailable() {
		return nil, fmt.Errorf("%w: ARGON2ID KDF provider not available in this Tongsuo build", ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: ARGON2ID derivation not yet wired", ErrUnsupported)
}

// validateHash 校验 md 是否为受支持的摘要算法。
//
// validateHash reports whether md is a supported digest algorithm.
func validateHash(md Hash) error {
	switch md {
	case HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512, HashSM3:
		return nil
	default:
		return fmt.Errorf("key: unsupported hash %q", md)
	}
}
