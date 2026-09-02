package rand_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rand"
)

// ExampleRead 演示使用 Read 填充字节切片为加密安全随机数。
//
// 返回值 n 始终等于 len(b)（除非底层失败），与 [io.Reader] 语义一致但语义更强。
//
// ExampleRead demonstrates filling a byte slice with cryptographically
// secure random bytes via Read.
//
// The return value n is always equal to len(b) on success (unless the
// underlying CSPRNG fails), matching io.Reader semantics but with a
// stronger guarantee: there is no short read on a successful return.
func ExampleRead() {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	fmt.Println(len(hex.EncodeToString(buf)))
	// Output: 32
}

// ExampleBytes 演示一次性获取指定长度的随机字节切片。
//
// 内部仍走 Read，只是封装了 make + 错误传播。
//
// ExampleBytes demonstrates one-shot allocation of a random byte slice.
//
// Internally it just delegates to Read, wrapping make with error
// propagation. n < 0 returns an error without allocating.
func ExampleBytes() {
	b, err := rand.Bytes(8)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(b))
	// Output: 8
}
