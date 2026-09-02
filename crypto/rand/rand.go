// Package rand 基于铜锁原生实现提供加密安全随机数生成，提供与 io.Reader 语义一致的 Read 以及一次性便捷函数 Bytes。
//
// 注意：包路径与 Go 标准库 crypto/rand 同名，调用方引用本包时**必须使用完整路径**
// 或起一个明确别名以避免被 stdlib 抢占：
//
//	import tongsrand "github.com/blue-cloud-net/tongsuo-go/crypto/rand"
//	// 或
//	import "github.com/blue-cloud-net/tongsuo-go/crypto/rand"
//
// 与 stdlib crypto/rand 的区别：本包底层走 Tongsuo RAND_bytes（OpenSSL CSPRNG），
// stdlib crypto/rand 在 Linux 上走 getrandom(2)。两者均属密码学安全随机数，
// 输出可用于密钥材料、nonce、salt 与 IV。
//
// Package rand provides a cryptographically secure random byte generator
// backed by the Tongsuo native library (OpenSSL CSPRNG via RAND_bytes).
//
// It exposes Read (matching io.Reader semantics: returns n == len(b) on
// success) and Bytes for one-shot allocation. The output of either
// function is suitable for key material, nonces, salts and IVs.
//
// Note: the import path of this package is the same as the standard
// library crypto/rand. Importers MUST use the full module path or an
// explicit alias to avoid being shadowed by the stdlib package — see the
// Chinese package comment above for the recommended idiom.
//
// The underlying entropy source is the OpenSSL RAND_bytes CSPRNG, which
// differs from the stdlib path on Linux (getrandom(2)). Both are
// considered cryptographically secure random sources.
package rand

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// Read 使用铜锁 RAND_bytes 将加密安全随机字节填充到 b。
// 返回实际写入的字节数（等于 len(b)）；底层失败时返回错误。
//
// 行为严格于 io.Reader 契约：成功时必定写入恰好 len(b) 字节（n == len(b)）；
// 当 len(b) == 0 时返回 (0, nil) 且不调用底层 CSPRNG。CSPRNG 失败时返回 (0, error)，
// 错误为铜锁 OpError。输出适用于密钥材料、nonce、salt 与 IV。
//
// Read fills b with cryptographically secure random bytes sourced from
// Tongsuo RAND_bytes.
//
// It implements io.Reader semantics but is stricter than the interface
// contract: on success it always writes exactly len(b) bytes (n == len(b))
// or, when len(b) == 0, returns (0, nil) without invoking the underlying
// CSPRNG. On CSPRNG failure it returns (0, error) wrapping a Tongsuo
// OpError. The output is suitable for key material, nonces, salts and IVs.
func Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !native.RAND_bytes(b) {
		return 0, core.NewOpError("rand: RAND_bytes", native.PopError())
	}
	return len(b), nil
}

// Bytes 返回 n 个加密安全随机字节。
// n < 0 时返回错误；n == 0 返回空切片（不调用底层 CSPRNG）。
//
// n > 0 时分配新切片，通过 Read 填充；任何 CSPRNG 失败回传给调用方。
//
// Bytes returns n cryptographically secure random bytes.
//
// n < 0 returns an error (negative length). n == 0 returns an empty
// slice without invoking the underlying CSPRNG. n > 0 allocates a fresh
// slice, fills it via Read, and propagates any CSPRNG failure back to
// the caller.
func Bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("rand: negative length %d", n)
	}
	b := make([]byte, n)
	if _, err := Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
