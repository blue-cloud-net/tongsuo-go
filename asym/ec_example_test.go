package asym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateEC 演示在 NIST P-256 上生成 ECDSA 密钥对。
func ExampleGenerateEC() {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	params, err := asym.Params(priv)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(priv.Algorithm(), params.Curve)
	// Output: EC prime256v1
}

// ExampleSignECDSA 演示 ECDSA-SHA256 签名验签往返。
func ExampleSignECDSA() {
	priv, _ := asym.GenerateEC(asym.CurveP384)
	data := []byte("tongsuo-go ecdsa example")

	sig, err := asym.SignECDSA(priv, data)
	if err != nil {
		fmt.Println("sign err:", err)
		return
	}
	if err := asym.VerifyECDSA(priv.Public(), data, sig); err != nil {
		fmt.Println("verify err:", err)
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// ExampleLoadPrivateKeyPEM 演示 ECDSA 私钥 PEM 导出与重新加载。
func ExampleLoadPrivateKeyPEM() {
	priv, _ := asym.GenerateEC(asym.CurveSecp256k1)

	pem, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		fmt.Println("marshal err:", err)
		return
	}
	loaded, err := asym.LoadPrivateKeyPEM(pem)
	if err != nil {
		fmt.Println("load err:", err)
		return
	}
	params, err := asym.Params(loaded)
	if err != nil {
		fmt.Println("params err:", err)
		return
	}
	fmt.Println(params.Curve)
	// Output: secp256k1
}
