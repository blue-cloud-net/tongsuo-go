package key_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/key"
)

// ExampleGenerateRSAKey 演示统合用法:生成 RSA 密钥对、导出 PEM、再解析回,
// 私钥与公钥均保持相等。
//
// ExampleGenerateRSAKey demonstrates unified usage: generating an RSA key
// pair, exporting PEM, parsing it back, and confirming that both the
// private and public keys round-trip equal.
func ExampleGenerateRSAKey() {
	priv, err := key.GenerateRSAKey(2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	privPEM, err := priv.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	pubPEM, err := priv.Public().Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	parsed, err := key.LoadPrivateKeyPEM(privPEM)
	if err != nil {
		fmt.Println(err)
		return
	}
	parsedPub, err := key.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s private match: %v; public match: %v\n",
		priv.Algorithm(), parsed.Equal(priv), parsedPub.Equal(priv.Public()))
	// Output: RSA private match: true; public match: true
}
