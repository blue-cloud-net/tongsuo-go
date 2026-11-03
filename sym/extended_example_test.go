package sym_test

import (
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// ExampleNewAESOCB 展示 AEAD 的密文与 tag 拼接形态。
//
// ExampleNewAESOCB demonstrates AEAD ciphertext with an appended tag.
func ExampleNewAESOCB() {
	aead, err := sym.NewAESOCB(make([]byte, 16))
	if err != nil {
		fmt.Println(err)
		return
	}
	// This fixed nonce is only for this one-message example; never reuse it with the same key.
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, []byte("hello"), []byte("header"))
	plain, err := aead.Open(nil, nonce, sealed, []byte("header"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(plain))
	// Output: hello
}
