package sym_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// ExampleEncryptSM4CCM 演示 SM4-CCM 的认证加密与解密。
//
// ExampleEncryptSM4CCM demonstrates SM4-CCM authenticated encryption and
// decryption.
func ExampleEncryptSM4CCM() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	nonce, _ := hex.DecodeString("00001234567800000000abcd")
	aad := []byte("aad")
	pt := []byte("tongsuo-go sm4-ccm")

	ct, tag, err := sym.EncryptSM4CCM(key, nonce, pt, aad)
	if err != nil {
		log.Fatal(err)
	}
	back, err := sym.DecryptSM4CCM(key, nonce, ct, tag, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(bytes.Equal(back, pt), len(tag))
	// Output: true 16
}

// ExampleEncryptSM4XTS 演示 SM4-XTS 的加解密（GB/T 17964-2021 向量）。
//
// ExampleEncryptSM4XTS demonstrates SM4-XTS encryption and decryption
// with the GB/T 17964-2021 test vector.
func ExampleEncryptSM4XTS() {
	key, _ := hex.DecodeString("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
		"BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0")
	tweak, _ := hex.DecodeString("9A785634120000000000000000000000")
	pt, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F10")

	ct, err := sym.EncryptSM4XTS(key, tweak, pt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.ToUpper(hex.EncodeToString(ct)))

	back, err := sym.DecryptSM4XTS(key, tweak, ct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(bytes.Equal(back, pt))
	// Output:
	// 9E52443A35410CA0BA5637B94C0766F469
	// true
}

// ExampleEncryptChaCha20 演示 ChaCha20 流密码（RFC 7539 §A.1 向量）。
//
// ExampleEncryptChaCha20 demonstrates the ChaCha20 stream cipher with the
// RFC 7539 section A.1 test vector.
func ExampleEncryptChaCha20() {
	key := make([]byte, sym.ChaCha20KeySize)
	iv, _ := hex.DecodeString("01000000000000000000000000000000")
	out, err := sym.EncryptChaCha20(key, iv, make([]byte, 16))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.ToLower(hex.EncodeToString(out)))
	// Output: 9f07e7be5551387a98ba977c732d080d
}

// ExampleNewAEAD 演示用统一的 AEAD 构造器创建 ChaCha20-Poly1305。
//
// ExampleNewAEAD demonstrates creating ChaCha20-Poly1305 through the
// unified AEAD constructor.
func ExampleNewAEAD() {
	key := bytes.Repeat([]byte{0x07}, sym.ChaCha20KeySize)
	aead, err := sym.NewAEAD("ChaCha20-Poly1305", key)
	if err != nil {
		log.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x01}, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, []byte("payload"), []byte("aad"))
	opened, err := aead.Open(nil, nonce, sealed, []byte("aad"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(opened), aead.Overhead())
	// Output: payload 16
}
