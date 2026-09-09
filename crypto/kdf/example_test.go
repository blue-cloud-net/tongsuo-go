// Package kdf 的外部可执行示例。
package kdf_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/kdf"
)

// ExampleHKDF 演示从共享秘密用 HKDF-SHA256 派生 32 字节密钥。
//
// ExampleHKDF demonstrates deriving a 32-byte key from a shared secret
// using HKDF-SHA256.
func ExampleHKDF() {
	secret := []byte("shared-secret")
	out, err := kdf.HKDF("SHA256", secret, nil, []byte("app-info"), 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(out))
	// Output: 32
}

// ExamplePBKDF2 演示用 PBKDF2-SHA256 从口令派生密钥。
//
// ExamplePBKDF2 demonstrates deriving a key from a password using
// PBKDF2-SHA256.
func ExamplePBKDF2() {
	out, err := kdf.PBKDF2("SHA256", []byte("password"), []byte("salt"), 1000, 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(out))
	// Output: 32
}
