package digest

import (
	"fmt"
	"hash"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	extdigest "github.com/blue-cloud-net/tongsuo-go/internal/digest"
)

// 扩展摘要算法的长度常量（`0.6.0` 新增）。SHA3 / KECCAK 的尺寸相同，分组长度
// 由海绵结构的速率决定（200 - 2×输出字节数）。
//
// Length constants for the extended digests added in `0.6.0`. SHA3 and
// KECCAK share the same output sizes; the block size follows the sponge
// rate (200 - 2×outputBytes).
const (
	// SHA256_192Size 为 SHA-256/192 摘要长度（24 字节，铜锁扩展）。
	//
	// SHA256_192Size is the SHA-256/192 digest length (24 bytes, a
	// Tongsuo extension).
	SHA256_192Size = 24
	// SHA256_192BlockSize 为 SHA-256/192 的内部分组长度。
	//
	// SHA256_192BlockSize is the internal block size of SHA-256/192.
	SHA256_192BlockSize = 64

	// SHA512_224Size 为 SHA-512/224 摘要长度（28 字节）。
	//
	// SHA512_224Size is the SHA-512/224 digest length (28 bytes).
	SHA512_224Size = 28
	// SHA512_224BlockSize 为 SHA-512/224 的内部分组长度（SHA-512 家族）。
	//
	// SHA512_224BlockSize is the internal block size of SHA-512/224
	// (the SHA-512 family).
	SHA512_224BlockSize = 128

	// SHA512_256Size 为 SHA-512/256 摘要长度（32 字节）。
	//
	// SHA512_256Size is the SHA-512/256 digest length (32 bytes).
	SHA512_256Size = 32
	// SHA512_256BlockSize 为 SHA-512/256 的内部分组长度。
	//
	// SHA512_256BlockSize is the internal block size of SHA-512/256.
	SHA512_256BlockSize = 128

	// SHA3_224Size / SHA3_224BlockSize 为 SHA3-224 的输出与分组长度。
	//
	// SHA3_224Size / SHA3_224BlockSize are the SHA3-224 output and block
	// lengths.
	SHA3_224Size      = 28
	SHA3_224BlockSize = 144
	// SHA3_256Size / SHA3_256BlockSize 为 SHA3-256 的输出与分组长度。
	//
	// SHA3_256Size / SHA3_256BlockSize are the SHA3-256 output and block
	// lengths.
	SHA3_256Size      = 32
	SHA3_256BlockSize = 136
	// SHA3_384Size / SHA3_384BlockSize 为 SHA3-384 的输出与分组长度。
	//
	// SHA3_384Size / SHA3_384BlockSize are the SHA3-384 output and block
	// lengths.
	SHA3_384Size      = 48
	SHA3_384BlockSize = 104
	// SHA3_512Size / SHA3_512BlockSize 为 SHA3-512 的输出与分组长度。
	//
	// SHA3_512Size / SHA3_512BlockSize are the SHA3-512 output and block
	// lengths.
	SHA3_512Size      = 64
	SHA3_512BlockSize = 72

	// KECCAK224Size / KECCAK224BlockSize 为 KECCAK-224 的输出与分组长度。
	//
	// KECCAK224Size / KECCAK224BlockSize are the KECCAK-224 output and
	// block lengths.
	KECCAK224Size      = 28
	KECCAK224BlockSize = 144
	// KECCAK256Size / KECCAK256BlockSize 为 KECCAK-256 的输出与分组长度。
	//
	// KECCAK256Size / KECCAK256BlockSize are the KECCAK-256 output and
	// block lengths.
	KECCAK256Size      = 32
	KECCAK256BlockSize = 136
	// KECCAK384Size / KECCAK384BlockSize 为 KECCAK-384 的输出与分组长度。
	//
	// KECCAK384Size / KECCAK384BlockSize are the KECCAK-384 output and
	// block lengths.
	KECCAK384Size      = 48
	KECCAK384BlockSize = 104
	// KECCAK512Size / KECCAK512BlockSize 为 KECCAK-512 的输出与分组长度。
	//
	// KECCAK512Size / KECCAK512BlockSize are the KECCAK-512 output and
	// block lengths.
	KECCAK512Size      = 64
	KECCAK512BlockSize = 72

	// SHAKE128Size / SHAKE128BlockSize 为 SHAKE128 的默认输出长度与分组长度；
	// 实际输出长度由调用方指定（推荐 ≥ 16）。
	//
	// SHAKE128Size / SHAKE128BlockSize are the SHAKE128 default output
	// length and block length; the actual output length is chosen by the
	// caller (16 or more is recommended).
	SHAKE128Size      = 16
	SHAKE128BlockSize = 168
	// SHAKE256Size / SHAKE256BlockSize 为 SHAKE256 的默认输出长度与分组长度。
	//
	// SHAKE256Size / SHAKE256BlockSize are the SHAKE256 default output
	// length and block length.
	SHAKE256Size      = 32
	SHAKE256BlockSize = 136
)

// NewSHA256_192 返回新的 SHA-256/192 哈希（hash.Hash）。
// 当前铜锁构建不提供该扩展时 panic——请先用 Available 探测。
//
// NewSHA256_192 returns a new SHA-256/192 hash implementing hash.Hash.
// It panics when the current Tongsuo build lacks the extension; probe
// with Available first.
func NewSHA256_192() hash.Hash {
	return mustHash("SHA256-192", core.SHA256_192(), SHA256_192Size, SHA256_192BlockSize)
}

// SumSHA256_192 返回 data 的 SHA-256/192 摘要（24 字节）。
//
// SumSHA256_192 returns the 24-byte SHA-256/192 digest of data.
func SumSHA256_192(data []byte) [SHA256_192Size]byte {
	var out [SHA256_192Size]byte
	mustSum("SHA256-192", core.SHA256_192(), data, out[:])
	return out
}

// NewSHA512_224 返回新的 SHA-512/224 哈希（hash.Hash）。
//
// NewSHA512_224 returns a new SHA-512/224 hash implementing hash.Hash.
func NewSHA512_224() hash.Hash {
	return mustHash("SHA512-224", core.SHA512_224(), SHA512_224Size, SHA512_224BlockSize)
}

// SumSHA512_224 返回 data 的 SHA-512/224 摘要（28 字节）。
//
// SumSHA512_224 returns the 28-byte SHA-512/224 digest of data.
func SumSHA512_224(data []byte) [SHA512_224Size]byte {
	var out [SHA512_224Size]byte
	mustSum("SHA512-224", core.SHA512_224(), data, out[:])
	return out
}

// NewSHA512_256 返回新的 SHA-512/256 哈希（hash.Hash）。
//
// NewSHA512_256 returns a new SHA-512/256 hash implementing hash.Hash.
func NewSHA512_256() hash.Hash {
	return mustHash("SHA512-256", core.SHA512_256(), SHA512_256Size, SHA512_256BlockSize)
}

// SumSHA512_256 返回 data 的 SHA-512/256 摘要（32 字节）。
//
// SumSHA512_256 returns the 32-byte SHA-512/256 digest of data.
func SumSHA512_256(data []byte) [SHA512_256Size]byte {
	var out [SHA512_256Size]byte
	mustSum("SHA512-256", core.SHA512_256(), data, out[:])
	return out
}

// NewSHA3_224 返回新的 SHA3-224 哈希（hash.Hash）。
//
// NewSHA3_224 returns a new SHA3-224 hash implementing hash.Hash.
func NewSHA3_224() hash.Hash {
	return mustHash("SHA3-224", core.SHA3_224(), SHA3_224Size, SHA3_224BlockSize)
}

// SumSHA3_224 返回 data 的 SHA3-224 摘要（28 字节）。
//
// SumSHA3_224 returns the 28-byte SHA3-224 digest of data.
func SumSHA3_224(data []byte) [SHA3_224Size]byte {
	var out [SHA3_224Size]byte
	mustSum("SHA3-224", core.SHA3_224(), data, out[:])
	return out
}

// NewSHA3_256 返回新的 SHA3-256 哈希（hash.Hash）。
//
// NewSHA3_256 returns a new SHA3-256 hash implementing hash.Hash.
func NewSHA3_256() hash.Hash {
	return mustHash("SHA3-256", core.SHA3_256(), SHA3_256Size, SHA3_256BlockSize)
}

// SumSHA3_256 返回 data 的 SHA3-256 摘要（32 字节）。
//
// SumSHA3_256 returns the 32-byte SHA3-256 digest of data.
func SumSHA3_256(data []byte) [SHA3_256Size]byte {
	var out [SHA3_256Size]byte
	mustSum("SHA3-256", core.SHA3_256(), data, out[:])
	return out
}

// NewSHA3_384 返回新的 SHA3-384 哈希（hash.Hash）。
//
// NewSHA3_384 returns a new SHA3-384 hash implementing hash.Hash.
func NewSHA3_384() hash.Hash {
	return mustHash("SHA3-384", core.SHA3_384(), SHA3_384Size, SHA3_384BlockSize)
}

// SumSHA3_384 返回 data 的 SHA3-384 摘要（48 字节）。
//
// SumSHA3_384 returns the 48-byte SHA3-384 digest of data.
func SumSHA3_384(data []byte) [SHA3_384Size]byte {
	var out [SHA3_384Size]byte
	mustSum("SHA3-384", core.SHA3_384(), data, out[:])
	return out
}

// NewSHA3_512 返回新的 SHA3-512 哈希（hash.Hash）。
//
// NewSHA3_512 returns a new SHA3-512 hash implementing hash.Hash.
func NewSHA3_512() hash.Hash {
	return mustHash("SHA3-512", core.SHA3_512(), SHA3_512Size, SHA3_512BlockSize)
}

// SumSHA3_512 返回 data 的 SHA3-512 摘要（64 字节）。
//
// SumSHA3_512 returns the 64-byte SHA3-512 digest of data.
func SumSHA3_512(data []byte) [SHA3_512Size]byte {
	var out [SHA3_512Size]byte
	mustSum("SHA3-512", core.SHA3_512(), data, out[:])
	return out
}

// SumSHAKE128 以指定输出长度计算 SHAKE128 摘要（可扩展输出）。
// outLen 必须大于 0；长度不足时返回错误。
//
// SumSHAKE128 computes a SHAKE128 digest of the requested length
// (extendable output). outLen must be positive.
func SumSHAKE128(data []byte, outLen int) ([]byte, error) {
	return sumXOF("SHAKE128", core.SHAKE128(), data, outLen)
}

// SumSHAKE256 以指定输出长度计算 SHAKE256 摘要（可扩展输出）。
// outLen 必须大于 0；长度不足时返回错误。
//
// SumSHAKE256 computes a SHAKE256 digest of the requested length
// (extendable output). outLen must be positive.
func SumSHAKE256(data []byte, outLen int) ([]byte, error) {
	return sumXOF("SHAKE256", core.SHAKE256(), data, outLen)
}

// NewKECCAK224 返回新的 KECCAK-224 哈希（hash.Hash）。
// 当前铜锁构建不提供时 panic——请先用 Available 探测。
//
// NewKECCAK224 returns a new KECCAK-224 hash implementing hash.Hash. It
// panics when unavailable in the current build; probe with Available.
func NewKECCAK224() hash.Hash {
	return mustHash("KECCAK-224", core.KECCAK224(), KECCAK224Size, KECCAK224BlockSize)
}

// SumKECCAK224 返回 data 的 KECCAK-224 摘要（28 字节）。
//
// SumKECCAK224 returns the 28-byte KECCAK-224 digest of data.
func SumKECCAK224(data []byte) [KECCAK224Size]byte {
	var out [KECCAK224Size]byte
	mustSum("KECCAK-224", core.KECCAK224(), data, out[:])
	return out
}

// NewKECCAK256 返回新的 KECCAK-256 哈希（hash.Hash）。
//
// NewKECCAK256 returns a new KECCAK-256 hash implementing hash.Hash.
func NewKECCAK256() hash.Hash {
	return mustHash("KECCAK-256", core.KECCAK256(), KECCAK256Size, KECCAK256BlockSize)
}

// SumKECCAK256 返回 data 的 KECCAK-256 摘要（32 字节）。
//
// SumKECCAK256 returns the 32-byte KECCAK-256 digest of data.
func SumKECCAK256(data []byte) [KECCAK256Size]byte {
	var out [KECCAK256Size]byte
	mustSum("KECCAK-256", core.KECCAK256(), data, out[:])
	return out
}

// NewKECCAK384 返回新的 KECCAK-384 哈希（hash.Hash）。
//
// NewKECCAK384 returns a new KECCAK-384 hash implementing hash.Hash.
func NewKECCAK384() hash.Hash {
	return mustHash("KECCAK-384", core.KECCAK384(), KECCAK384Size, KECCAK384BlockSize)
}

// SumKECCAK384 返回 data 的 KECCAK-384 摘要（48 字节）。
//
// SumKECCAK384 returns the 48-byte KECCAK-384 digest of data.
func SumKECCAK384(data []byte) [KECCAK384Size]byte {
	var out [KECCAK384Size]byte
	mustSum("KECCAK-384", core.KECCAK384(), data, out[:])
	return out
}

// NewKECCAK512 返回新的 KECCAK-512 哈希（hash.Hash）。
//
// NewKECCAK512 returns a new KECCAK-512 hash implementing hash.Hash.
func NewKECCAK512() hash.Hash {
	return mustHash("KECCAK-512", core.KECCAK512(), KECCAK512Size, KECCAK512BlockSize)
}

// SumKECCAK512 返回 data 的 KECCAK-512 摘要（64 字节）。
//
// SumKECCAK512 returns the 64-byte KECCAK-512 digest of data.
func SumKECCAK512(data []byte) [KECCAK512Size]byte {
	var out [KECCAK512Size]byte
	mustSum("KECCAK-512", core.KECCAK512(), data, out[:])
	return out
}

// Available 报告当前铜锁构建是否真的提供该摘要算法。
// 与 Names() 的关系：Names() 是编译期清单，Available 是运行时事实——典型差异是
// 铜锁 8.4.0（OpenSSL 3.0.3 底座）不提供 KECCAK-* 与 SHA-256/192。
//
// Available reports whether the installed Tongsuo build really provides
// the named digest. Names() is the compile-time list whereas Available is
// the runtime fact; the typical difference is that Tongsuo 8.4.0 (OpenSSL
// 3.0.3 base) has no KECCAK-* and no SHA-256/192.
func Available(name string) bool {
	a, err := lookup(name)
	if err != nil {
		return false
	}
	return a.desc() != nil
}

// mustHash 按描述符构造 hash.Hash；描述符不可用时 panic（与既有 New* 一致）。
//
// mustHash builds a hash.Hash from the descriptor and panics when the
// descriptor is unavailable (matching the existing New* helpers).
func mustHash(name string, d *core.Digest, size, block int) hash.Hash {
	if d == nil {
		panic(fmt.Sprintf("digest: %s: %v", name, ErrUnsupported))
	}
	return extdigest.NewHash(d, size, block)
}

// mustSum 用描述符一次性求摘要并拷贝进 out；不可用或失败时 panic。
//
// mustSum hashes data into out and panics when the descriptor is
// unavailable or the operation fails.
func mustSum(name string, d *core.Digest, data, out []byte) {
	if d == nil {
		panic(fmt.Sprintf("digest: %s: %v", name, ErrUnsupported))
	}
	sum, err := d.OneShot(data)
	if err != nil {
		panic(err)
	}
	copy(out, sum)
}

// sumXOF 用 XOF 描述符按指定长度求摘要。
//
// sumXOF hashes data through an XOF descriptor with the given length.
func sumXOF(name string, d *core.Digest, data []byte, outLen int) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("digest: %s: %w", name, ErrUnsupported)
	}
	if outLen <= 0 {
		return nil, fmt.Errorf("digest: %s: invalid output length %d", name, outLen)
	}
	sum, err := d.XOFOneShot(data, outLen)
	if err != nil {
		return nil, fmt.Errorf("digest: %s: %w", name, err)
	}
	return sum, nil
}
