package sm3_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm3"
)

// ExampleSum 演示一次性 SM3 计算。
//
// 输出 32 字节（256 位）。示例取 GB/T 32905-2016 附录 A 中 "abc" 的标准向量。
func ExampleSum() {
	sum := sm3.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
}

// ExampleNew 演示流式 SM3。
//
// 等价于 Sum：多次 Write 累加数据后 Sum 一次性返回 32 字节摘要。
func ExampleNew() {
	h := sm3.New()
	h.Write([]byte("ab"))
	h.Write([]byte("c"))
	sum := h.Sum(nil)
	fmt.Println(hex.EncodeToString(sum))
	// Output: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
}

// ExampleNew_reset 演示 Reset 重置摘要状态后可复用同一 hash 实例。
func ExampleNew_reset() {
	h := sm3.New()
	h.Write([]byte("abc"))
	first := h.Sum(nil)

	h.Reset()
	h.Write([]byte("abc"))
	second := h.Sum(nil)

	fmt.Println(hex.EncodeToString(first) == hex.EncodeToString(second))
	// Output: true
}
