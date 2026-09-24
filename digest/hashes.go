package digest

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	extdigest "github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

// NewSM3 返回新的 SM3 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewSM3 returns a new SM3 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
func NewSM3() hash.Hash {
	return extdigest.NewHash(core.SM3(), SM3Size, SM3BlockSize)
}

// SumSM3 返回 data 的 SM3 摘要（GB/T 32905-2016）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumSM3 returns the SM3 digest of data per GB/T 32905-2016. It panics
// only if the underlying Tongsuo operation fails, which does not occur
// in normal use.
func SumSM3(data []byte) [SM3Size]byte {
	sum, err := core.SM3().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [SM3Size]byte
	copy(out[:], sum)
	return out
}

// NewMD5 返回新的 MD5 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// 安全提示：MD5 已不适用于数字签名，仅可用于兼容既有格式与完整性校验。
//
// NewMD5 returns a new MD5 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
//
// Security note: MD5 is no longer suitable for digital signatures; use it
// only for compatibility with legacy formats and integrity checks.
func NewMD5() hash.Hash {
	return extdigest.NewHash(core.MD5(), MD5Size, MD5BlockSize)
}

// SumMD5 返回 data 的 MD5 摘要（RFC 1321）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumMD5 returns the MD5 digest of data per RFC 1321. It panics only if
// the underlying Tongsuo operation fails, which does not occur in normal
// use.
func SumMD5(data []byte) [MD5Size]byte {
	sum, err := core.MD5().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [MD5Size]byte
	copy(out[:], sum)
	return out
}

// NewSHA1 返回新的 SHA-1 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// 安全提示：SHA-1 已不适用于数字签名，仅可用于兼容既有格式与完整性校验。
//
// NewSHA1 returns a new SHA-1 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
//
// Security note: SHA-1 is no longer suitable for digital signatures; use
// it only for compatibility with legacy formats and integrity checks.
func NewSHA1() hash.Hash {
	return extdigest.NewHash(core.SHA1(), SHA1Size, SHA1BlockSize)
}

// SumSHA1 返回 data 的 SHA-1 摘要（FIPS 180-4）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumSHA1 returns the SHA-1 digest of data per FIPS 180-4. It panics only
// if the underlying Tongsuo operation fails, which does not occur in
// normal use.
func SumSHA1(data []byte) [SHA1Size]byte {
	sum, err := core.SHA1().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [SHA1Size]byte
	copy(out[:], sum)
	return out
}

// NewSHA224 返回新的 SHA-224 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewSHA224 returns a new SHA-224 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
func NewSHA224() hash.Hash {
	return extdigest.NewHash(core.SHA224(), SHA224Size, SHA224BlockSize)
}

// SumSHA224 返回 data 的 SHA-224 摘要（FIPS 180-4）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumSHA224 returns the SHA-224 digest of data per FIPS 180-4. It panics
// only if the underlying Tongsuo operation fails, which does not occur in
// normal use.
func SumSHA224(data []byte) [SHA224Size]byte {
	sum, err := core.SHA224().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [SHA224Size]byte
	copy(out[:], sum)
	return out
}

// NewSHA256 返回新的 SHA-256 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewSHA256 returns a new SHA-256 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
func NewSHA256() hash.Hash {
	return extdigest.NewHash(core.SHA256(), SHA256Size, SHA256BlockSize)
}

// SumSHA256 返回 data 的 SHA-256 摘要（FIPS 180-4）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumSHA256 returns the SHA-256 digest of data per FIPS 180-4. It panics
// only if the underlying Tongsuo operation fails, which does not occur in
// normal use.
func SumSHA256(data []byte) [SHA256Size]byte {
	sum, err := core.SHA256().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [SHA256Size]byte
	copy(out[:], sum)
	return out
}

// NewSHA384 返回新的 SHA-384 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewSHA384 returns a new SHA-384 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
func NewSHA384() hash.Hash {
	return extdigest.NewHash(core.SHA384(), SHA384Size, SHA384BlockSize)
}

// SumSHA384 返回 data 的 SHA-384 摘要（FIPS 180-4）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumSHA384 returns the SHA-384 digest of data per FIPS 180-4. It panics
// only if the underlying Tongsuo operation fails, which does not occur in
// normal use.
func SumSHA384(data []byte) [SHA384Size]byte {
	sum, err := core.SHA384().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [SHA384Size]byte
	copy(out[:], sum)
	return out
}

// NewSHA512 返回新的 SHA-512 哈希（hash.Hash），支持流式写入与 Reset。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewSHA512 returns a new SHA-512 hash implementing hash.Hash, supporting
// streaming writes and reuse via Reset. It panics only if the underlying
// Tongsuo initialization fails, which does not occur in normal use.
func NewSHA512() hash.Hash {
	return extdigest.NewHash(core.SHA512(), SHA512Size, SHA512BlockSize)
}

// SumSHA512 返回 data 的 SHA-512 摘要（FIPS 180-4）。
// 仅当底层铜锁操作失败（正常使用不会发生）时 panic。
//
// SumSHA512 returns the SHA-512 digest of data per FIPS 180-4. It panics
// only if the underlying Tongsuo operation fails, which does not occur in
// normal use.
func SumSHA512(data []byte) [SHA512Size]byte {
	sum, err := core.SHA512().OneShot(data)
	if err != nil {
		panic(err)
	}
	var out [SHA512Size]byte
	copy(out[:], sum)
	return out
}
