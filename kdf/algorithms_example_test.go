package kdf_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/kdf"
)

// ExampleScrypt 演示使用 scrypt 从口令派生密钥。
//
// ExampleScrypt demonstrates deriving a key from a password with scrypt.
func ExampleScrypt() {
	key, err := kdf.Scrypt([]byte("password"), []byte("NaCl"), 1024, 8, 16, 0, 32)
	fmt.Println(len(key), err)
	// Output: 32 <nil>
}

// ExampleX963KDF 演示 ANSI X9.63 KDF 的确定性派生。
//
// ExampleX963KDF demonstrates a deterministic ANSI X9.63 KDF derivation.
func ExampleX963KDF() {
	secret, _ := hex.DecodeString("fd17198b89ab39c4ab5d7cca363b82f9fd7e23c3984dc8a2")
	info, _ := hex.DecodeString("856a53f3e36a26bbc5792879f307cce2")

	out, err := kdf.X963KDF(kdf.HashSHA1, secret, info, 8)
	fmt.Printf("%x %v\n", out, err)
	// Output: 6e5fad865cb4a51c <nil>
}

// ExampleTLS13KDFExtract 演示 TLS 1.3 的 HKDF-Extract 步。
//
// ExampleTLS13KDFExtract demonstrates the TLS 1.3 HKDF-Extract step.
func ExampleTLS13KDFExtract() {
	ikm, _ := hex.DecodeString("f8af6aea2d397baf2948a25b2834200692cff17eee9165e4e27babee9edefd05")

	prk, err := kdf.TLS13KDFExtract(kdf.HashSHA256, ikm, nil)
	fmt.Printf("%x %v\n", prk, err)
	// Output: 153b6394a9c03cf3f5accc6e455a7693281138a1bcfa3803c26735dd1194d216 <nil>
}

// ExampleKBKDF 演示 SP 800-108 KBKDF（HMAC 计数器模式）派生。
//
// ExampleKBKDF demonstrates an SP 800-108 KBKDF derivation in HMAC
// counter mode.
func ExampleKBKDF() {
	out, err := kdf.KBKDF(&kdf.KBKDFOptions{
		Digest:  kdf.HashSHA256,
		MAC:     "HMAC",
		Mode:    "COUNTER",
		Secret:  []byte("0123456789abcdef0123456789abcdef"),
		Label:   []byte("label"),
		Context: []byte("context"),
		R:       32,
	}, 16)
	fmt.Println(len(out), err)
	// Output: 16 <nil>
}

// ExampleDerive_sskdf 演示通过按名入口使用 SSKDF（名称大小写不敏感），
// 并观察未知算法名的错误。
//
// ExampleDerive_sskdf demonstrates dispatching to SSKDF through the
// by-name entry (case-insensitively) and the error for an unknown name.
func ExampleDerive_sskdf() {
	secret := []byte("shared secret")
	out, err := kdf.Derive("sskdf", &kdf.Options{
		Digest: kdf.HashSHA256,
		Secret: secret,
		Info:   []byte("context"),
		Length: 16,
	})
	fmt.Println(len(out), err)

	_, err = kdf.Derive("NOSUCHKDF", &kdf.Options{Length: 16})
	fmt.Println(err != nil)
	// Output:
	// 16 <nil>
	// true
}
