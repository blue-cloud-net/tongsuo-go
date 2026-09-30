package mac

import (
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// NewHMACSM3 返回 HMAC-SM3 的 hash.Hash（标签 32 字节）。
// key 长度任意。仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// NewHMACSM3 returns a hash.Hash implementing HMAC-SM3 (32-byte tag).
// key may be any length. It panics only if the underlying Tongsuo
// initialization fails, which does not occur in normal use.
func NewHMACSM3(key []byte) hash.Hash {
	return newHMAC(key, core.SM3())
}

// SumHMACSM3 一次性计算 HMAC-SM3 并返回 32 字节标签。
// 等价于分配一个 NewHMACSM3 实例、写入 data、复制标签。
//
// SumHMACSM3 returns the 32-byte HMAC-SM3 tag of data under key.
func SumHMACSM3(key, data []byte) []byte {
	return oneShot(NewHMACSM3(key), data)
}

// NewHMACMD5 返回 HMAC-MD5 的 hash.Hash（标签 16 字节）。
//
// 安全提示：MD5 已不抗碰撞，本函数仅用于兼容遗留系统；新协议推荐 NewHMACSHA256
// 或 NewHMACSM3。
//
// NewHMACMD5 returns a hash.Hash implementing HMAC-MD5 (16-byte tag).
//
// Security note: MD5 is collision-prone; this helper exists for
// compatibility only — prefer NewHMACSHA256 or NewHMACSM3 for new
// protocols.
func NewHMACMD5(key []byte) hash.Hash {
	return newHMAC(key, core.MD5())
}

// SumHMACMD5 一次性计算 HMAC-MD5 并返回 16 字节标签。
//
// SumHMACMD5 returns the 16-byte HMAC-MD5 tag of data under key.
func SumHMACMD5(key, data []byte) []byte {
	return oneShot(NewHMACMD5(key), data)
}

// NewHMACSHA1 返回 HMAC-SHA1 的 hash.Hash（标签 20 字节）。
//
// 安全提示：SHA-1 用于数字签名已不抗碰撞，但作为 MAC 在兼容场景仍可使用；新协议
// 推荐 NewHMACSHA256 或 NewHMACSM3。
//
// NewHMACSHA1 returns a hash.Hash implementing HMAC-SHA1 (20-byte tag).
//
// Security note: SHA-1 is collision-prone for digital signatures; HMAC-
// SHA1 remains acceptable as a MAC for compatibility — prefer
// NewHMACSHA256 or NewHMACSM3 for new protocols.
func NewHMACSHA1(key []byte) hash.Hash {
	return newHMAC(key, core.SHA1())
}

// SumHMACSHA1 一次性计算 HMAC-SHA1 并返回 20 字节标签。
//
// SumHMACSHA1 returns the 20-byte HMAC-SHA1 tag of data under key.
func SumHMACSHA1(key, data []byte) []byte {
	return oneShot(NewHMACSHA1(key), data)
}

// NewHMACSHA224 返回 HMAC-SHA224 的 hash.Hash（标签 28 字节）。
//
// NewHMACSHA224 returns a hash.Hash implementing HMAC-SHA224 (28-byte tag).
func NewHMACSHA224(key []byte) hash.Hash {
	return newHMAC(key, core.SHA224())
}

// SumHMACSHA224 一次性计算 HMAC-SHA224 并返回 28 字节标签。
//
// SumHMACSHA224 returns the 28-byte HMAC-SHA224 tag of data under key.
func SumHMACSHA224(key, data []byte) []byte {
	return oneShot(NewHMACSHA224(key), data)
}

// NewHMACSHA256 返回 HMAC-SHA256 的 hash.Hash（标签 32 字节）。新协议推荐。
//
// NewHMACSHA256 returns a hash.Hash implementing HMAC-SHA256 (32-byte tag).
// Recommended for new protocols.
func NewHMACSHA256(key []byte) hash.Hash {
	return newHMAC(key, core.SHA256())
}

// SumHMACSHA256 一次性计算 HMAC-SHA256 并返回 32 字节标签。
//
// SumHMACSHA256 returns the 32-byte HMAC-SHA256 tag of data under key.
func SumHMACSHA256(key, data []byte) []byte {
	return oneShot(NewHMACSHA256(key), data)
}

// NewHMACSHA384 返回 HMAC-SHA384 的 hash.Hash（标签 48 字节）。
//
// NewHMACSHA384 returns a hash.Hash implementing HMAC-SHA384 (48-byte tag).
func NewHMACSHA384(key []byte) hash.Hash {
	return newHMAC(key, core.SHA384())
}

// SumHMACSHA384 一次性计算 HMAC-SHA384 并返回 48 字节标签。
//
// SumHMACSHA384 returns the 48-byte HMAC-SHA384 tag of data under key.
func SumHMACSHA384(key, data []byte) []byte {
	return oneShot(NewHMACSHA384(key), data)
}

// NewHMACSHA512 返回 HMAC-SHA512 的 hash.Hash（标签 64 字节）。
// 性能敏感场景可按需截断标签。
//
// NewHMACSHA512 returns a hash.Hash implementing HMAC-SHA512 (64-byte tag).
// For performance-sensitive cases the 64-byte tag can be truncated.
func NewHMACSHA512(key []byte) hash.Hash {
	return newHMAC(key, core.SHA512())
}

// SumHMACSHA512 一次性计算 HMAC-SHA512 并返回 64 字节标签。
//
// SumHMACSHA512 returns the 64-byte HMAC-SHA512 tag of data under key.
func SumHMACSHA512(key, data []byte) []byte {
	return oneShot(NewHMACSHA512(key), data)
}

// oneShot 把「分配、写、收标签」三步折叠为一次性入口。
// 写入与取标签均不会失败（HMAC_CTX_Update/Sum 在正常路径不返回错误）；
// 因此本函数 panic 分支理论上不可达。
//
// oneShot folds allocate / write / read-tag into a single helper. Write
// and Sum do not fail on the normal path, so the panic branches are
// unreachable in practice.
func oneShot(h hash.Hash, data []byte) []byte {
	if _, err := h.Write(data); err != nil {
		panic(err)
	}
	return h.Sum(nil)
}
