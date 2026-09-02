package rsa_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
	rsaxml "github.com/blue-cloud-net/tongsuo-go/xml/rsa"
)
// ExampleMarshalPrivate 演示把 RSA 私钥导出为 .NET RSAKeyValue XML 格式。
// 该 XML 格式在 C# / .NET Framework 中通过 RSA.ToXmlString() 产生，
// 含 Modulus / Exponent / P / Q / DP / DQ / InverseQ / D 全部 CRT 参数。
// 适用场景：与 .NET 系统互操作，如需在跨语言环境中传输 RSA 私钥。
//
// ExampleMarshalPrivate demonstrates exporting an RSA private key to
// the .NET RSAKeyValue XML format. This format is produced by
// RSA.ToXmlString() in C# / .NET Framework and contains Modulus,
// Exponent, P, Q, DP, DQ, InverseQ and D (all CRT parameters). Use it
// when interoperating with .NET systems that need to transport an RSA
// private key across language boundaries.
func ExampleMarshalPrivate() {
	priv, _ := rsa.GenerateKey(2048)
	xmlBytes, err := rsaxml.MarshalPrivate(priv)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(xmlBytes[:14]))
	// Output: <RSAKeyValue>
}
// ExampleUnmarshalPrivate 演示从 .NET RSAKeyValue XML 反向还原 RSA 私钥。
// 输入 XML 须包含完整字段；缺失 D/P/Q 等会失败。
//
// ExampleUnmarshalPrivate demonstrates parsing a .NET RSAKeyValue XML
// document back into an RSA private key. The input XML must include
// the full set of fields; missing D, P or Q (or any other required
// field) results in an error.
func ExampleUnmarshalPrivate() {
	priv, _ := rsa.GenerateKey(2048)
	xmlBytes, _ := rsaxml.MarshalPrivate(priv)

	loaded, err := rsaxml.UnmarshalPrivate(xmlBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(loaded.Public().Params().N.BitLen())
	// Output: 2048
}
