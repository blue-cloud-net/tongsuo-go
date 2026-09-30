package mac_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/mac"
)

// ExampleSumHMACSM3 演示一次性 HMAC-SM3。
// key = 0x00..0x07，data = "abc"；向量由铜锁 openssl mac 实测取得。
//
// ExampleSumHMACSM3 demonstrates a one-shot HMAC-SM3.
func ExampleSumHMACSM3() {
	key, _ := hex.DecodeString("0001020304050607")
	fmt.Println(hex.EncodeToString(mac.SumHMACSM3(key, []byte("abc"))))
	// Output: d3586fa146dfd27a8f39152121541cdac7727b0d434521351eddc7e4a17c7155
}

// ExampleSumHMACSHA256 演示一次性 HMAC-SHA256。
//
// ExampleSumHMACSHA256 demonstrates a one-shot HMAC-SHA256.
func ExampleSumHMACSHA256() {
	key, _ := hex.DecodeString("0001020304050607")
	fmt.Println(hex.EncodeToString(mac.SumHMACSHA256(key, []byte("abc"))))
	// Output: d639301952b492e23d24be078f62922f9a890e85d6753fd6c3cd5372b35a2326
}

// ExampleSumHMACSHA224 演示一次性 HMAC-SHA224（本版新增 SHA-224 HMAC）。
//
// ExampleSumHMACSHA224 demonstrates a one-shot HMAC-SHA224 (added in this version).
func ExampleSumHMACSHA224() {
	key, _ := hex.DecodeString("0001020304050607")
	fmt.Println(hex.EncodeToString(mac.SumHMACSHA224(key, []byte("abc"))))
	// Output: a512d16e3316e173605d4fff52594141a63186664ef054a635727fb5
}

// ExampleSumHMACMD5 演示一次性 HMAC-MD5（兼容遗留场景）。
//
// ExampleSumHMACMD5 demonstrates a one-shot HMAC-MD5 (legacy compatibility).
func ExampleSumHMACMD5() {
	key, _ := hex.DecodeString("0001020304050607")
	fmt.Println(hex.EncodeToString(mac.SumHMACMD5(key, []byte("abc"))))
	// Output: 4dd165b813cfe2016dc3a0c77de5eabb
}

// ExampleNewHMACSM3 演示流式 HMAC-SM3：多次 Write 累加后取标签。
//
// ExampleNewHMACSM3 demonstrates streaming HMAC-SM3.
func ExampleNewHMACSM3() {
	h := mac.NewHMACSM3([]byte("my secret"))
	h.Write([]byte("ab"))
	h.Write([]byte("c"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: bd6108c925114222adf85b44867401309171d9fc24518f3fb24fc7b4f9a07678
}

// ExampleNew_reset 演示 Reset 后复用同一 HMAC 实例。
//
// ExampleNew_reset demonstrates reusing one HMAC instance after Reset.
func ExampleNew_reset() {
	h := mac.NewHMACSM3([]byte("k"))
	h.Write([]byte("abc"))
	first := h.Sum(nil)
	h.Reset()
	h.Write([]byte("abc"))
	second := h.Sum(nil)
	fmt.Println(hex.EncodeToString(first) == hex.EncodeToString(second))
	// Output: true
}

// ExampleSum_byName 演示按算法名一次性计算 HMAC。
//
// ExampleSum_byName demonstrates a one-shot HMAC by algorithm name.
func ExampleSum_byName() {
	key, _ := hex.DecodeString("0001020304050607")
	tag, err := mac.Sum("HMAC-SHA384", key, []byte("abc"), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(tag))
	// Output: 17830995892e761fc7d8d1bc911896c06c97a86b1ad496a072101b4491253fe7cb9ee46007ec047fe9aa9be1d70d4a6a
}

// ExampleNames 演示查询本版支持的算法名列表。
//
// ExampleNames demonstrates listing the algorithm names supported by this version.
func ExampleNames() {
	for _, n := range mac.Names() {
		fmt.Println(n)
	}
	// Output:
	// HMAC-SM3
	// HMAC-MD5
	// HMAC-SHA1
	// HMAC-SHA224
	// HMAC-SHA256
	// HMAC-SHA384
	// HMAC-SHA512
}
