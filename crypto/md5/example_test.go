package md5_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/md5"
)

// ExampleSum 演示一次性 MD5 计算。
//
// 注意：MD5 已不抗碰撞，请勿用于数字签名或证书指纹等依赖抗碰撞性的场景。
func ExampleSum() {
	sum := md5.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: 900150983cd24fb0d6963f7d28e17f72
}

// ExampleNew 演示流式 MD5。
func ExampleNew() {
	h := md5.New()
	h.Write([]byte("abc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: 900150983cd24fb0d6963f7d28e17f72
}
