package asym_test

import (
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// ExampleMarshalPKCS8 展示指定 PBES2 与 PRF 的 DER 私钥往返。
//
// ExampleMarshalPKCS8 demonstrates a DER key round trip with explicit PBES2 and PRF.
func ExampleMarshalPKCS8() {
	key, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer asym.Close(key)
	opts := &asym.PKCS8Options{Encrypt: true, Iterations: 10000, PRF: "hmacWithSHA256", Passphrase: "example password"}
	der, err := asym.MarshalPKCS8(key, meta.FormatDER, opts)
	if err != nil {
		fmt.Println(err)
		return
	}
	loaded, err := asym.LoadPKCS8(der, meta.FormatDER, true, opts.Passphrase)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer asym.Close(loaded)
	match, err := asym.Match(loaded, key.Public())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(match)
	// Output: true
}
