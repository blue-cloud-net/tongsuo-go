package rand

import (
	"fmt"
	"io"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Read 使用铜锁 RAND_bytes 将加密安全随机字节填充到 b。
// 返回实际写入的字节数（成功时等于 len(b)）；底层失败时返回错误。
//
// 行为严格于 io.Reader 契约：成功时必定写入恰好 len(b) 字节（n == len(b)）；
// 当 len(b) == 0 时返回 (0, nil) 且不调用底层 CSPRNG。CSPRNG 失败时返回
// (0, error)，错误为铜锁 OpError。输出适用于密钥材料、nonce、salt 与 IV。
//
// 实现细节：本包不直接依赖 internal/native（保持三层架构依赖方向），而是
// 通过 core.RandomBytes 这个 core 层薄包装转发到底层 RAND_bytes。
//
// Read fills b with cryptographically secure random bytes sourced from
// Tongsuo RAND_bytes.
//
// It implements io.Reader semantics but is stricter than the interface
// contract: on success it always writes exactly len(b) bytes (n == len(b))
// or, when len(b) == 0, returns (0, nil) without invoking the underlying
// CSPRNG. On CSPRNG failure it returns (0, error) wrapping a Tongsuo
// OpError. The output is suitable for key material, nonces, salts and IVs.
//
// Implementation note: to preserve the three-layer dependency direction
// (API → core → native) the package forwards RAND_bytes calls via the
// core.RandomBytes thin wrapper rather than importing internal/native.
func Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := core.RandomBytes(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Bytes 返回 n 个加密安全随机字节。
// n < 0 时返回错误；n == 0 返回空切片（不调用底层 CSPRNG）。
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

// Reader 返回一个无限随机源，实现 io.Reader；每次 Read 都直接走底层
// RAND_bytes，不持有任何状态。注意 io.Copy 会在循环内反复调用 Read，每次
// 都会新生成随机字节——适合密钥材料、nonce、salt 等不可预测输入，不适合
// 对可复现性有要求的场景（PRNG 种子流等）。
//
// Reader returns an infinite random source implementing io.Reader. Each
// Read delegates to RAND_bytes and holds no state across calls. Note
// that io.Copy loops over Read, each iteration generating fresh random
// bytes — this is appropriate for key material, nonces, salts and IVs
// but NOT for scenarios that require determinism (e.g. PRNG seed
// streams).
func Reader() io.Reader {
	return reader{}
}

// reader 是 Reader() 返回的无限 io.Reader 实现。
//
// reader is the io.Reader implementation returned by Reader().
type reader struct{}

// Read 调用底层 RAND_bytes 填充 p。返回 (len(p), nil) 或 (0, error)。
//
// Read fills p via RAND_bytes. Returns (len(p), nil) or (0, error).
func (reader) Read(p []byte) (int, error) {
	return Read(p)
}
