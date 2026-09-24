package kdf_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/kdf"
)

// ExampleHKDF 演示用 RFC 5869 附录 A.1 标准向量计算 HKDF-SHA256。
//
// ExampleHKDF demonstrates computing HKDF-SHA256 with the RFC 5869
// Appendix A.1 standard test vector.
func ExampleHKDF() {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	out, err := kdf.HKDF(kdf.HashSHA256, ikm, salt, info, 42)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(out))
	// Output: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
}

// ExamplePBKDF2 演示一次性 PBKDF2-SHA256 派生。
//
// ExamplePBKDF2 demonstrates a one-shot PBKDF2-SHA256 derivation.
func ExamplePBKDF2() {
	out, err := kdf.PBKDF2(kdf.HashSHA256, []byte("password"), []byte("salt"), 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(out))
	// Output: 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
}

// ExampleDerive 演示按算法名一次性派生（使用 RFC 5869 A.1 标准向量）。
//
// ExampleDerive demonstrates a one-shot KDF by algorithm name using the
// RFC 5869 Appendix A.1 standard test vector.
func ExampleDerive() {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	out, err := kdf.Derive("HKDF", &kdf.Options{
		Digest: kdf.HashSHA256,
		Secret: ikm,
		Salt:   salt,
		Info:   info,
		Length: 42,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(out))
	// Output: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
}

// ExampleNames 演示查询本版支持的 KDF 算法名。
//
// ExampleNames demonstrates listing the KDF algorithm names supported by
// this version.
func ExampleNames() {
	for _, n := range kdf.Names() {
		fmt.Println(n)
	}
	// Output:
	// HKDF
	// PBKDF2
}

// ExampleArgon2IDAvailable 演示探测当前构建是否带 Argon2ID provider。
//
// ExampleArgon2IDAvailable demonstrates probing whether the current build
// ships the Argon2ID provider.
func ExampleArgon2IDAvailable() {
	fmt.Println(kdf.Argon2IDAvailable())
	// Output: false
}
