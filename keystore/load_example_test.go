package keystore_test

import (
	"bytes"
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/keystore"
)

// ExampleLoadAllFromReader 展示自动读取同一 PEM 中的私钥与公钥。
//
// ExampleLoadAllFromReader demonstrates detecting private/public keys in one PEM input.
func ExampleLoadAllFromReader() {
	key, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer asym.Close(key)
	priv, err := key.MarshalPrivateKeyPEM()
	if err != nil {
		fmt.Println(err)
		return
	}
	pub, err := key.Public().MarshalPublicKeyPEM()
	if err != nil {
		fmt.Println(err)
		return
	}
	keys, err := keystore.LoadAllFromReader(bytes.NewReader(append(priv, pub...)), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, k := range keys {
		defer asym.Close(k)
	}
	fmt.Println(len(keys))
	// Output: 2
}
