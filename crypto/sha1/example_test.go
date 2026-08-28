package sha1_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sha1"
)

// ExampleSum 演示一次性 SHA-1 计算。
//
// 注意：SHA-1 已不抗碰撞，请勿用于新协议的数字签名或证书指纹。
func ExampleSum() {
	sum := sha1.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: a9993e364706816aba3e25717850c26c9cd0d89d
}

// ExampleNew 演示流式 SHA-1。
func ExampleNew() {
	h := sha1.New()
	h.Write([]byte("abc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: a9993e364706816aba3e25717850c26c9cd0d89d
}
