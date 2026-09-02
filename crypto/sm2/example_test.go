package sm2_test

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
)
// ExampleGenerateKey 演示生成 SM2 密钥对与 PEM 序列化。
// 私钥以 PKCS#8 编码（"BEGIN PRIVATE KEY"），公钥以 SubjectPublicKeyInfo 编码
// （"BEGIN PUBLIC KEY"）；与铜锁 / OpenSSL 命令行输出互通。
//
// ExampleGenerateKey demonstrates generating an SM2 key pair and serializing
// it to PEM. The private key is encoded as PKCS#8 ("-----BEGIN PRIVATE KEY-----")
// and the public key as SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----"),
// interoperable with the Tongsuo/OpenSSL command line.
func ExampleGenerateKey() {
	priv, err := sm2.GenerateKey()
	if err != nil {
		panic(err)
	}
	privPEM, err := priv.MarshalPEM()
	if err != nil {
		panic(err)
	}
	pubPEM, err := priv.Public().MarshalPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(privPEM[:27]))
	fmt.Println(string(pubPEM[:26]))
	// Output:
	// -----BEGIN PRIVATE KEY-----
	// -----BEGIN PUBLIC KEY-----
}
// ExampleSign 演示使用 SM2 私钥签名与公钥验签（SM2withSM3，ASN.1 DER）。
// 默认 userId 为 GM/T 0003-2012 规定的 "1234567812345678"；验签时也需使用同一 userId，
// 否则失败。
//
// ExampleSign demonstrates signing with an SM2 private key and verifying with
// the matching public key (SM2withSM3, ASN.1 DER). The default user identifier
// is the string "1234567812345678" required by GM/T 0003-2012; verification
// must use the same user identifier or it will fail.
func ExampleSign() {
	priv, _ := sm2.GenerateKey()
	msg := []byte("hello SM2")

	sig, err := sm2.Sign(priv, msg)
	if err != nil {
		panic(err)
	}
	fmt.Println(sm2.Verify(priv.Public(), msg, sig))
	// Output: <nil>
}
// ExampleEncrypt 演示 SM2 公钥加密与私钥解密。
// 输出为 ASN.1 DER 格式（内含 C1C3C2 顺序），与铜锁 `openssl pkeyutl` 输出一致。
//
// ExampleEncrypt demonstrates public-key encryption and private-key decryption
// with SM2. The ciphertext is emitted in ASN.1 DER (internal C1C3C2 order),
// matching the output of Tongsuo's `openssl pkeyutl` command.
func ExampleEncrypt() {
	priv, _ := sm2.GenerateKey()
	msg := []byte("hello SM2 encryption")

	ct, err := sm2.Encrypt(priv.Public(), msg)
	if err != nil {
		panic(err)
	}
	pt, err := sm2.Decrypt(priv, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pt))
	// Output: hello SM2 encryption
}
// ExampleFormat 演示 SM2 密文顺序格式互转。
// 裸格式 "c1c3c2" 与 "c1c2c3" 互转；与 DER 互转要求 C1 为未压缩点。
//
// ExampleFormat demonstrates converting between SM2 ciphertext representations:
// DER, raw "c1c3c2", and raw "c1c2c3". Conversions involving DER require an
// uncompressed C1 point.
func ExampleFormat() {
	priv, _ := sm2.GenerateKey()
	ct, _ := sm2.Encrypt(priv.Public(), []byte("data"))

	// DER → c1c3c2 → c1c2c3 → DER 的完整往返
	c132, err := sm2.Format(ct, "der", "c1c3c2")
	if err != nil {
		panic(err)
	}
	c123, err := sm2.Format(c132, "c1c3c2", "c1c2c3")
	if err != nil {
		panic(err)
	}
	back, err := sm2.Format(c123, "c1c2c3", "der")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(ct) == len(back))
	// Output: true
}
