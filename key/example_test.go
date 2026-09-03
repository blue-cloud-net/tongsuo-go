package key_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/key"
)

// ExampleGenerateSymmetricKey 演示生成、导出并解析回一个随机 SM4 对称密钥。
//
// ExampleGenerateSymmetricKey demonstrates generating, exporting and
// parsing back a fresh random SM4 symmetric key.
func ExampleGenerateSymmetricKey() {
	k, err := key.GenerateSymmetricKey(key.AlgSM4)
	if err != nil {
		fmt.Println(err)
		return
	}
	pemBytes, err := k.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	parsed, err := key.ParseSymmetricKey(pemBytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s %d-byte key round-tripped: %v\n", k.Algorithm(), k.Size(), parsed.Equal(k))
	// Output: SM4 16-byte key round-tripped: true
}
