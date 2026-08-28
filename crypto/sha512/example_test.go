package sha512_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sha512"
)

// ExampleSum 演示一次性 SHA-512 计算。
func ExampleSum() {
	sum := sha512.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
}

// ExampleNew 演示流式 SHA-512。
func ExampleNew() {
	h := sha512.New()
	h.Write([]byte("abc"))
	fmt.Println(len(h.Sum(nil)))
	// Output: 64
}
