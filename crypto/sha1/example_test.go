package sha1_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sha1"
)
// ExampleSum 演示一次性 SHA-1 计算。
//
// 注意：SHA-1 已不抗碰撞，请勿用于新协议的数字签名或证书指纹。
//
// ExampleSum demonstrates one-shot SHA-1 computation.
//
// Note: SHA-1 is no longer collision-resistant (SHAttered, 2017) and
// must not be used for new digital signatures or certificate
// fingerprints. It remains acceptable for non-cryptographic checksums
// and for HMAC-SHA1 in legacy systems.
func ExampleSum() {
	sum := sha1.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: a9993e364706816aba3e25717850c26c9cd0d89d
}
// ExampleNew 演示流式 SHA-1。
// 通过 hash.Hash 接口支持分段 Write 与 Reset 复用同一实例处理多条消息。
//
// ExampleNew demonstrates streaming SHA-1 via the hash.Hash interface,
// supporting segmented Write calls and Reset reuse between messages.
func ExampleNew() {
	h := sha1.New()
	h.Write([]byte("abc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: a9993e364706816aba3e25717850c26c9cd0d89d
}
