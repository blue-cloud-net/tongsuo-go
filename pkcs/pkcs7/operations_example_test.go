package pkcs7_test

import (
	"bytes"
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/pkcs/pkcs7"
	"github.com/blue-cloud-net/tongsuo-go/x509"
	"time"
)

// ExampleSign 演示 PKCS#7 签名、显式信任验签和结果释放。
//
// ExampleSign demonstrates PKCS#7 signing, explicit trust verification and result cleanup.
func ExampleSign() {
	key, err := asym.GenerateRSA(2048)
	if err != nil {
		panic(err)
	}
	defer asym.Close(key)
	cert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "PKCS7 signer"), 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), key.Public(), key)
	if err != nil {
		panic(err)
	}
	defer cert.Close()
	der, err := pkcs7.Sign([]byte("signed content"), &pkcs7.SignOptions{SignerCert: cert, SignerKey: key})
	if err != nil {
		panic(err)
	}
	roots := x509.NewStore()
	defer roots.Close()
	if err := roots.AddCert(cert); err != nil {
		panic(err)
	}
	result, err := pkcs7.Verify(der, &pkcs7.VerifyOptions{Roots: roots})
	if err != nil {
		panic(err)
	}
	defer result.Close()
	fmt.Println(string(result.Content), result.TrustVerified)
	// Output: signed content true
}

// ExampleEncrypt 演示 RSA 接收者信封的加解密；CBC 解密不代表完整性认证。
//
// ExampleEncrypt demonstrates RSA recipient envelope encryption/decryption; CBC decryption does not authenticate integrity.
func ExampleEncrypt() {
	key, err := asym.GenerateRSA(2048)
	if err != nil {
		panic(err)
	}
	defer asym.Close(key)
	cert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "recipient"), 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), key.Public(), key)
	if err != nil {
		panic(err)
	}
	defer cert.Close()
	message := []byte("envelope")
	der, err := pkcs7.Encrypt(message, &pkcs7.EncryptOptions{Recipients: []*x509.Certificate{cert}})
	if err != nil {
		panic(err)
	}
	plain, err := pkcs7.Decrypt(der, &pkcs7.DecryptOptions{RecipientCert: cert, RecipientKey: key})
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.Equal(message, plain))
	// Output: true
}
