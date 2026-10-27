package mac

import "hash"

// 新HMAC 返回基于 SM3 的 HMAC 计算器（hash.Hash）。
//
// NewHMACSM3 returns an HMAC computation over SM3 (hash.Hash).
func NewHMACSM3(key []byte) hash.Hash {
	return mustHMAC("HMAC-SM3", key)
}

// SumHMACSM3 一次性计算基于 SM3 的 HMAC 值。
//
// SumHMACSM3 computes the HMAC over SM3 in one shot.
func SumHMACSM3(key, data []byte) []byte {
	return mustSum("HMAC-SM3", key, data)
}

// NewHMACMD5 返回基于 MD5 的 HMAC 计算器（hash.Hash）。
//
// NewHMACMD5 returns an HMAC computation over MD5 (hash.Hash).
func NewHMACMD5(key []byte) hash.Hash {
	return mustHMAC("HMAC-MD5", key)
}

// SumHMACMD5 一次性计算基于 MD5 的 HMAC 值。
//
// SumHMACMD5 computes the HMAC over MD5 in one shot.
func SumHMACMD5(key, data []byte) []byte {
	return mustSum("HMAC-MD5", key, data)
}

// NewHMACSHA1 返回基于 SHA-1 的 HMAC 计算器（hash.Hash）。
//
// NewHMACSHA1 returns an HMAC computation over SHA-1 (hash.Hash).
func NewHMACSHA1(key []byte) hash.Hash {
	return mustHMAC("HMAC-SHA1", key)
}

// SumHMACSHA1 一次性计算基于 SHA-1 的 HMAC 值。
//
// SumHMACSHA1 computes the HMAC over SHA-1 in one shot.
func SumHMACSHA1(key, data []byte) []byte {
	return mustSum("HMAC-SHA1", key, data)
}

// NewHMACSHA224 返回基于 SHA-224 的 HMAC 计算器（hash.Hash）。
//
// NewHMACSHA224 returns an HMAC computation over SHA-224 (hash.Hash).
func NewHMACSHA224(key []byte) hash.Hash {
	return mustHMAC("HMAC-SHA224", key)
}

// SumHMACSHA224 一次性计算基于 SHA-224 的 HMAC 值。
//
// SumHMACSHA224 computes the HMAC over SHA-224 in one shot.
func SumHMACSHA224(key, data []byte) []byte {
	return mustSum("HMAC-SHA224", key, data)
}

// NewHMACSHA256 返回基于 SHA-256 的 HMAC 计算器（hash.Hash）。
//
// NewHMACSHA256 returns an HMAC computation over SHA-256 (hash.Hash).
func NewHMACSHA256(key []byte) hash.Hash {
	return mustHMAC("HMAC-SHA256", key)
}

// SumHMACSHA256 一次性计算基于 SHA-256 的 HMAC 值。
//
// SumHMACSHA256 computes the HMAC over SHA-256 in one shot.
func SumHMACSHA256(key, data []byte) []byte {
	return mustSum("HMAC-SHA256", key, data)
}

// NewHMACSHA384 返回基于 SHA-384 的 HMAC 计算器（hash.Hash）。
//
// NewHMACSHA384 returns an HMAC computation over SHA-384 (hash.Hash).
func NewHMACSHA384(key []byte) hash.Hash {
	return mustHMAC("HMAC-SHA384", key)
}

// SumHMACSHA384 一次性计算基于 SHA-384 的 HMAC 值。
//
// SumHMACSHA384 computes the HMAC over SHA-384 in one shot.
func SumHMACSHA384(key, data []byte) []byte {
	return mustSum("HMAC-SHA384", key, data)
}

// NewHMACSHA512 返回基于 SHA-512 的 HMAC 计算器（hash.Hash）。
//
// NewHMACSHA512 returns an HMAC computation over SHA-512 (hash.Hash).
func NewHMACSHA512(key []byte) hash.Hash {
	return mustHMAC("HMAC-SHA512", key)
}

// SumHMACSHA512 一次性计算基于 SHA-512 的 HMAC 值。
//
// SumHMACSHA512 computes the HMAC over SHA-512 in one shot.
func SumHMACSHA512(key, data []byte) []byte {
	return mustSum("HMAC-SHA512", key, data)
}

// mustHMAC 按名构造 HMAC 计算器；失败时 panic。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// mustHMAC builds an HMAC computation by name and panics on failure. It
// panics only if the underlying Tongsuo initialisation fails, which does
// not occur in normal use.
func mustHMAC(name string, key []byte) hash.Hash {
	h, err := New(name, key, nil)
	if err != nil {
		panic(err)
	}
	return h
}

// mustSum 按名一次性计算 HMAC；失败时 panic。
// 仅当底层铜锁初始化失败（正常使用不会发生）时 panic。
//
// mustSum computes an HMAC in one shot by name and panics on failure. It
// panics only if the underlying Tongsuo initialisation fails, which does
// not occur in normal use.
func mustSum(name string, key, data []byte) []byte {
	tag, err := Sum(name, key, data, nil)
	if err != nil {
		panic(err)
	}
	return tag
}
