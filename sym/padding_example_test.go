package sym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/sym"
)

// ExampleSupports 展示如何在不提交数据的前提下校验「算法名 × 填充」组合。
//
// ExampleSupports shows how to validate an algorithm-name/padding
// combination without submitting any data.
func ExampleSupports() {
	fmt.Println(sym.Supports("AES-128-CBC", sym.PaddingPKCS7))
	fmt.Println(sym.Supports("AES-128-CBC", sym.PaddingZero))
	fmt.Println(sym.Supports("AES-128-CTR", sym.PaddingPKCS7))

	paddings, _ := sym.Paddings("SM4-CBC")
	fmt.Println(paddings)
	// Output:
	// true <nil>
	// true <nil>
	// false <nil>
	// [pkcs7 zero none]
}
