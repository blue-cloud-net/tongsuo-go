package rand_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rand"
)

// ExampleRead 演示使用 Read 填充字节切片为加密安全随机数。
//
// 返回值 n 始终等于 len(b)（除非底层失败），与 [io.Reader] 语义一致但语义更强。
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
func ExampleBytes() {
	b, err := rand.Bytes(8)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(b))
	// Output: 8
}
