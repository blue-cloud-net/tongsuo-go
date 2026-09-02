package md5_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/md5"
)
// ExampleSum 演示一次性 MD5 计算。
//
// 注意：MD5 已不抗碰撞，请勿用于数字签名或证书指纹等依赖抗碰撞性的场景。
//
// ExampleSum demonstrates one-shot MD5 computation.
//
// Note: MD5 is no longer collision-resistant (chosen-prefix collisions
// are practical) and must not be used for digital signatures or
// certificate fingerprints. It remains acceptable for HMAC-MD5 and
// non-adversarial checksums.
func ExampleSum() {
	sum := md5.Sum([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum[:]))
	// Output: 900150983cd24fb0d6963f7d28e17f72
}
// ExampleNew 演示流式 MD5。
// 通过 hash.Hash 接口支持分段 Write 与 Reset 复用同一实例处理多条消息。
//
// ExampleNew demonstrates streaming MD5 via the hash.Hash interface,
// supporting segmented Write calls and Reset reuse between messages.
func ExampleNew() {
	h := md5.New()
	h.Write([]byte("abc"))
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
	// Output: 900150983cd24fb0d6963f7d28e17f72
}
