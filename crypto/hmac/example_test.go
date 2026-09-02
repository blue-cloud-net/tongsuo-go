package hmac_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/hmac"
)
// ExampleSumSM3 演示一次性计算 HMAC-SM3。
//
// HMAC-SM3 用于国密合规场景下的消息认证；输出 32 字节（与 SM3 摘要长度相同）。
//
// ExampleSumSM3 demonstrates one-shot HMAC-SM3 computation.
//
// The output is a 32-byte tag (the SM3 digest size), suitable for GM/T
// compliant message authentication scenarios.
func ExampleSumSM3() {
	mac := hmac.SumSM3([]byte("secret-key"), []byte("hello world"))
	fmt.Println(hex.EncodeToString(mac))
}
// ExampleNewSM3 演示流式 HMAC-SM3。
// 等价于 SumSM3，支持分段写入与 Reset 复用。
//
// ExampleNewSM3 demonstrates streaming HMAC-SM3 via the hash.Hash
// interface. It is functionally equivalent to SumSM3 but supports
// segmented Write calls and Reset reuse between messages under the
// same key.
func ExampleNewSM3() {
	h := hmac.NewSM3([]byte("k"))
	h.Write([]byte("hello"))
	h.Write([]byte(" world"))
	fmt.Println(len(h.Sum(nil)))
	// Output: 32
}
// ExampleSumSHA256 演示 HMAC-SHA256 一次性计算。
// 返回 32 字节标签（SHA-256 摘要长度）。
//
// ExampleSumSHA256 demonstrates one-shot HMAC-SHA256 computation. The
// returned tag is 32 bytes (the SHA-256 digest size).
func ExampleSumSHA256() {
	fmt.Println(len(hmac.SumSHA256([]byte("k"), []byte("ping"))))
	// Output: 32
}
// ExampleNewSHA512 演示流式 HMAC-SHA512。
// 返回 64 字节标签（SHA-512 摘要长度）。
//
// ExampleNewSHA512 demonstrates streaming HMAC-SHA512 via the hash.Hash
// interface. The returned tag is 64 bytes (the SHA-512 digest size).
func ExampleNewSHA512() {
	h := hmac.NewSHA512([]byte("k"))
	h.Write([]byte("ping"))
	fmt.Println(len(h.Sum(nil)))
	// Output: 64
}
