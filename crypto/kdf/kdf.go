// Package kdf 基于铜锁原生实现密钥派生函数（KDF）。
// 提供 HKDF（RFC 5869）与 PBKDF2（RFC 8018）的一次性派生，以及 Argon2id
// 可用性探测。底层经内部 core 层调用 Tongsuo EVP_KDF；摘要以规范化名称
// 表达（如 "SHA256"、"SHA1"、"SHA512"、"SM3"），大小写与连字符均不敏感。
//
// Package kdf provides key derivation functions (KDF) backed by the
// Tongsuo native library. It exposes one-shot HKDF (RFC 5869) and PBKDF2
// (RFC 8018) derivation plus an Argon2id availability probe. The
// underlying core layer calls the Tongsuo EVP_KDF; digests are expressed
// by normalised names (for example "SHA256", "SHA1", "SHA512" or "SM3")
// and matching is case- and hyphen-insensitive.
package kdf

import (
	"fmt"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// HKDF 使用 HKDF（RFC 5869，extract-and-expand）从 secret 派生 length 字节。
//
// mdName 为摘要算法名（如 "SHA256"、"SHA1"、"SHA512"、"SM3"），规范化后传给
// 底层；secret 不能为空；salt/info 可为空（空 salt 按 RFC 5869 等价于 HashLen
// 字节的零盐）。length 必须为正整数。失败时返回包装 OpError 的错误。
//
// HKDF derives length bytes from secret using HKDF (RFC 5869,
// extract-and-expand). mdName is the message-digest name (for example
// "SHA256", "SHA1", "SHA512" or "SM3") and is normalised before being
// forwarded to the underlying implementation; secret must be non-empty;
// salt and info may be empty (an empty salt is equivalent to a zero salt
// of HashLen bytes per RFC 5869). length must be positive. On failure it
// returns an error wrapping an OpError.
func HKDF(mdName string, secret, salt, info []byte, length int) ([]byte, error) {
	if mdName == "" {
		return nil, fmt.Errorf("kdf: empty digest name")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("kdf: empty HKDF secret")
	}
	if length <= 0 {
		return nil, fmt.Errorf("kdf: invalid output length %d", length)
	}
	return core.HKDF(normalizeDigest(mdName), secret, salt, info, length)
}

// PBKDF2 使用 PBKDF2（RFC 8018）从口令派生 keyLen 字节。
//
// mdName 为摘要算法名（如 "SHA1"、"SHA256"）；iter 为迭代次数（>=1）；
// password 不能为空。失败时返回包装 OpError 的错误。
//
// PBKDF2 derives keyLen bytes from a password using PBKDF2 (RFC 8018).
// mdName is the message-digest name (for example "SHA1" or "SHA256");
// iter is the iteration count (>= 1); password must be non-empty. On
// failure it returns an error wrapping an OpError.
func PBKDF2(mdName string, password, salt []byte, iter, keyLen int) ([]byte, error) {
	if mdName == "" {
		return nil, fmt.Errorf("kdf: empty digest name")
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
	return core.PBKDF2(normalizeDigest(mdName), password, salt, iter, keyLen)
}

// Argon2IDAvailable 报告当前 Tongsuo 构建是否提供 ARGON2ID KDF。
//
// Argon2id 需要 OpenSSL 3.2+ 且编译含对应 provider；当前构建通常不可用。
//
// Argon2IDAvailable reports whether the current Tongsuo build provides
// the ARGON2ID KDF. Argon2id requires OpenSSL 3.2+ with the provider
// compiled in; the current build usually does not provide it.
func Argon2IDAvailable() bool { return core.Argon2IDAvailable() }

// normalizeDigest 把摘要名规范为底层期望的写法：去首尾空白、转大写并移除连字符。
// 例如 "sha-256" / "SHA256" 均归一为 "SHA256"。未知名称原样保留（透传底层，
// 由其报错）。
//
// normalizeDigest canonicalises a digest name for the underlying layer:
// it trims surrounding whitespace, uppercases and strips hyphens, so for
// example both "sha-256" and "SHA256" map to "SHA256". Unknown names are
// passed through unchanged and left to the underlying layer to reject.
func normalizeDigest(name string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(name), "-", ""))
}
