package core

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// HKDF 使用 HKDF（RFC 5869，extract-and-expand）从 secret 派生 length 字节。
// mdName 为摘要算法名（如 "SHA256"、"SHA1"、"SM3"）；secret 不能为空；
// salt/info 可为空。失败时返回包装了 OpError 的错误。
//
// HKDF derives length bytes from secret using HKDF (RFC 5869,
// extract-and-expand). mdName is the message-digest name (for example
// "SHA256", "SHA1" or "SM3"); secret must be non-empty; salt and info may be
// empty. On failure it returns an error wrapping an OpError.
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
	out := make([]byte, length)
	if !native.EVP_KDF_HKDF(mdName, 0 /* extract-and-expand */, secret, salt, info, out) {
		return nil, NewOpError("kdf: HKDF", native.PopError())
	}
	return out, nil
}

// PBKDF2 使用 PBKDF2（RFC 8018）从口令派生 keyLen 字节。
// mdName 为摘要算法名（如 "SHA1"、"SHA256"）；iter 为迭代次数（>=1）。
// password 不能为空。失败时返回包装了 OpError 的错误。
//
// PBKDF2 derives keyLen bytes from a password using PBKDF2 (RFC 8018).
// mdName is the message-digest name (for example "SHA1" or "SHA256"); iter is
// the iteration count (>= 1); password must be non-empty. On failure it
// returns an error wrapping an OpError.
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
	out := make([]byte, keyLen)
	if !native.EVP_KDF_PBKDF2(mdName, password, salt, iter, out) {
		return nil, NewOpError("kdf: PBKDF2", native.PopError())
	}
	return out, nil
}

// Argon2IDAvailable 报告当前 Tongsuo 构建是否提供 ARGON2ID KDF。
// Argon2id 需要 OpenSSL 3.2+ 且编译含对应 provider；本库当前构建通常不可用。
//
// Argon2IDAvailable reports whether the current Tongsuo build provides the
// ARGON2ID KDF. Argon2id requires OpenSSL 3.2+ with the provider compiled in;
// the current build of this library usually does not provide it.
func Argon2IDAvailable() bool {
	return native.EVP_KDF_Available("ARGON2ID")
}
