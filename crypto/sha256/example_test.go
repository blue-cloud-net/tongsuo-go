package sha256_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sha256"
)

// ExampleSum 演示一次性 SHA-256 计算。
func ExampleSum() {
	sum := sha256.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}

// ExampleNew 演示流式 SHA-256。
func ExampleNew() {
	h := sha256.New()
	h.Write([]byte("a"))
	h.Write([]byte("bc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
