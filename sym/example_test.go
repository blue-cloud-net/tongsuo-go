package sym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// ExampleNewCipher 演示按算法名构造 AES-128-CBC 分组密码。
func ExampleNewCipher() {
	block, err := sym.NewCipher("AES-128-CBC", make([]byte, sym.AES128KeySize))
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(block.BlockSize())
	// Output: 16
}

// ExampleEncrypt 演示按名一次性 AES-256-CBC 加密再解密。
func ExampleEncrypt() {
	key := make([]byte, sym.AES256KeySize) // 调用方负责清零
	iv := make([]byte, sym.BlockSize)
	plaintext := []byte("tongsuo-go sym example")

	ciphertext, err := sym.Encrypt("AES-256-CBC", key, iv, plaintext, nil)
	if err != nil {
		fmt.Println("encrypt err:", err)
		return
	}
	recovered, err := sym.Decrypt("AES-256-CBC", key, iv, ciphertext, nil)
	if err != nil {
		fmt.Println("decrypt err:", err)
		return
	}
	fmt.Println(string(recovered))
	// Output: tongsuo-go sym example
}

// ExampleNewGCM 演示 SM4-GCM AEAD：Seal 与 Open 往返。
func ExampleNewGCM() {
	key := make([]byte, sym.SM4KeySize)
	nonce := make([]byte, sym.NonceSize)
	aad := []byte("header-v1")
	plaintext := []byte("aead-message")

	aead, err := sym.NewGCM("SM4-GCM", key)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	recovered, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		fmt.Println("open err:", err)
		return
	}
	fmt.Println(string(recovered))
	// Output: aead-message
}

// ExampleNewAESKey 演示 AESKey 构造与按名分发。
func ExampleNewAESKey() {
	raw := []byte("0123456789abcdef") // 16 字节 AES-128 key
	k, err := sym.NewAESKey(raw)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(k.Algorithm(), k.Size())
	// Output: AES-128 16
}

// ExampleNames 列出当前支持的全部算法名。
func ExampleNames() {
	fmt.Println(len(sym.Names()) >= 14)
	// Output: true
}
