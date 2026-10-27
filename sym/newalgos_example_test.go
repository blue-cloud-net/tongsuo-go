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
