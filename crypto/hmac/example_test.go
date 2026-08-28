package hmac_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/hmac"
)

// ExampleSumSM3 演示一次性计算 HMAC-SM3。
//
// HMAC-SM3 用于国密合规场景下的消息认证；输出 32 字节（与 SM3 摘要长度相同）。
func ExampleSumSM3() {
	mac := hmac.SumSM3([]byte("secret-key"), []byte("hello world"))
	fmt.Println(hex.EncodeToString(mac))
}

// ExampleNewSM3 演示流式 HMAC-SM3。
//
// 等价于 SumSM3，支持分段写入与 Reset 复用。
func ExampleNewSM3() {
	h := hmac.NewSM3([]byte("k"))
	h.Write([]byte("hello"))
	h.Write([]byte(" world"))
	fmt.Println(len(h.Sum(nil)))
	// Output: 32
}

// ExampleSumSHA256 演示 HMAC-SHA256 一次性计算。
func ExampleSumSHA256() {
	fmt.Println(len(hmac.SumSHA256([]byte("k"), []byte("ping"))))
	// Output: 32
}

// ExampleNewSHA512 演示流式 HMAC-SHA512。
func ExampleNewSHA512() {
	h := hmac.NewSHA512([]byte("k"))
	h.Write([]byte("ping"))
	fmt.Println(len(h.Sum(nil)))
	// Output: 64
}
