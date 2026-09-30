package asym_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleGenerateSM2 演示生成 SM2 密钥对并导出 PEM。
func ExampleGenerateSM2() {
	priv, err := asym.GenerateSM2()
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	pem, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(len(pem) > 0)
	// Output: true
}

// ExampleSign 演示 SM2withSM3 签名与验签往返。
func ExampleSign() {
	priv, _ := asym.GenerateSM2()
	data := []byte("tongsuo-go asym example")

	sig, err := asym.Sign(priv, data)
	if err != nil {
		fmt.Println("sign err:", err)
		return
	}
	if err := asym.Verify(priv.Public(), data, sig); err != nil {
		fmt.Println("verify err:", err)
		return
	}
	fmt.Println("ok")
	// Output: ok
}

// ExampleEncrypt 演示 SM2 公钥加密 + 私钥解密。
func ExampleEncrypt() {
	priv, _ := asym.GenerateSM2()
	data := []byte("aead-message")

	ct, err := asym.Encrypt(priv.Public(), data)
	if err != nil {
		fmt.Println("encrypt err:", err)
		return
	}
	pt, err := asym.Decrypt(priv, ct)
	if err != nil {
		fmt.Println("decrypt err:", err)
		return
	}
	fmt.Println(string(pt))
	// Output: aead-message
}

// ExampleFormat 演示 SM2 密文格式转换（DER ↔ C1C3C2 ↔ C1C2C3）。
func ExampleFormat() {
	priv, _ := asym.GenerateSM2()
	data := []byte("format-conversion")

	der, _ := asym.Encrypt(priv.Public(), data)
	// DER → C1C3C2 → DER 往返：两条 DER 应字节级一致。
	c132, err := asym.Format(der, "der", "c1c3c2")
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	back, err := asym.Format(c132, "c1c3c2", "der")
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	fmt.Println(bytesEqual(der, back))
	// Output: true
}

// bytesEqual 是为 Example 提供的本地辅助（避免与 bytes 包冲突）。
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ExampleAlgorithm 演示 Algorithm 字符串约定。
func ExampleAlgorithm() {
	priv, _ := asym.GenerateSM2()
	fmt.Println(priv.Algorithm())
	// Output: SM2
}
