package sm4_test

import (
	"crypto/cipher"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm4"
)
// ExampleNewCipher 演示构造 SM4 cipher.Block。
// SM4 密钥固定 16 字节；返回标准库 cipher.Block 接口。
//
// ExampleNewCipher demonstrates constructing an SM4 cipher.Block.
// The key must be exactly 16 bytes; the returned value satisfies the standard
// cipher.Block interface.
func ExampleNewCipher() {
	key := []byte("0123456789abcdef")
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	fmt.Println(block.BlockSize())
	// Output: 16
}
// ExampleEncryptCBC 演示 SM4-CBC 加密与解密（PKCS7 填充）。
// IV 长度必须为 BlockSize（16 字节）且与加密时一致。
//
// ExampleEncryptCBC demonstrates SM4-CBC encryption and decryption with PKCS7
// padding. The IV must be exactly BlockSize (16 bytes) and match the value
// used for encryption.
func ExampleEncryptCBC() {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	plaintext := []byte("hello SM4")

	ciphertext, err := sm4.EncryptCBC(key, iv, plaintext)
	if err != nil {
		panic(err)
	}
	decrypted, err := sm4.DecryptCBC(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypted))
	// Output: hello SM4
}
// ExampleNewGCM 演示 SM4-GCM AEAD。
// GCM 是认证加密（AEAD）：输出密文 + 16 字节认证标签，可验证密文与 AAD 完整性。
//
// ExampleNewGCM demonstrates SM4-GCM authenticated encryption (AEAD). GCM
// produces ciphertext plus a 16-byte authentication tag, which verifies both
// the ciphertext and the additional authenticated data (AAD).
func ExampleNewGCM() {
	key := []byte("0123456789abcdef")
	nonce := make([]byte, sm4.NonceSize) // 96 位 Nonce，须唯一不可重用

	block, _ := sm4.NewCipher(key)
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	plaintext := []byte("secret message")
	aad := []byte("metadata")

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	fmt.Println(len(sealed))

	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(opened))
	// Output:
	// 30
	// secret message
}
// ExampleEncryptCTR 演示 SM4-CTR 流模式（无填充，加密 = 解密）。
// CTR 为流密码：密文长度等于明文长度；IV 必须唯一。
//
// ExampleEncryptCTR demonstrates SM4-CTR stream mode (no padding; encryption
// and decryption are the same operation). CTR is a stream cipher, so the
// ciphertext length equals the plaintext length; the IV must be unique per
// key.
func ExampleEncryptCTR() {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	plaintext := []byte("hello SM4-CTR")

	ciphertext, err := sm4.EncryptCTR(key, iv, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(ciphertext))

	decrypted, err := sm4.DecryptCTR(key, iv, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypted))
	// Output:
	// 13
	// hello SM4-CTR
}
