package sha256_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sha256"
)
// ExampleSum 演示一次性 SHA-256 计算。
// 返回 32 字节摘要。
//
// ExampleSum demonstrates one-shot SHA-256 computation. The returned
// digest is 32 bytes.
func ExampleSum() {
	sum := sha256.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
// ExampleNew 演示流式 SHA-256。
// 通过 hash.Hash 接口支持分段 Write 与 Reset 复用同一实例处理多条消息。
//
// ExampleNew demonstrates streaming SHA-256 via the hash.Hash interface,
// supporting segmented Write calls and Reset reuse between messages.
func ExampleNew() {
	h := sha256.New()
	h.Write([]byte("a"))
	h.Write([]byte("bc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
