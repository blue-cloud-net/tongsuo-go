package sym_test

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// ExampleNewAESGCMSIV 演示 AEAD 追加 tag 和显式处理旧版本不支持。
// 实际应用必须安全生成密钥并为每条消息生成新 nonce；调用方负责清零源密钥。
//
// ExampleNewAESGCMSIV demonstrates appended AEAD tags and unavailable-support handling.
// Applications must securely generate keys and fresh nonces per message; callers must wipe source keys.
func ExampleNewAESGCMSIV() {
	aead, err := sym.NewAESGCMSIV(make([]byte, 16))
	if errors.Is(err, sym.ErrUnsupported) {
		fmt.Println("AES-GCM-SIV unavailable")
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	nonce := make([]byte, 12) // Example only; generate a fresh nonce for real messages.
	sealed := aead.Seal(nil, nonce, []byte("message"), []byte("header"))
	plain, err := aead.Open(nil, nonce, sealed, []byte("header"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(plain))
}
