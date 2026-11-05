package asym_test

import (
	"errors"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleSignEd25519ph 演示原消息与上下文签验，以及原生不支持时的处理。
//
// ExampleSignEd25519ph demonstrates message/context signing and explicit unavailable-support handling.
func ExampleSignEd25519ph() {
	key, err := asym.GenerateEd25519()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer asym.Close(key)
	msg, context := []byte("message"), []byte("application/v1")
	sig, err := asym.SignEd25519ph(key, msg, context)
	if errors.Is(err, asym.ErrUnsupported) {
		fmt.Println("Ed25519ph unavailable")
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(asym.VerifyEd25519ph(key.Public(), msg, sig, context) == nil)
}
