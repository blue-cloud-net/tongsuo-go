// Package rsa 提供 RSA 密钥的 .NET RSAKeyValue XML 序列化。
//
// 与铜锁 openssl / .NET 互操作：Marshal* 将本库 RSA 密钥导出为 XML，
// Unmarshal* 从 XML 解析并加载为本库 RSA 密钥。
//
// 注意：本包路径为 xml/rsa，但包名为 rsa；调用方通常需用别名
// `import rsaxml "github.com/.../xml/rsa"` 以避免与 crypto/rsa 冲突。
package rsa

import (
	stdrsa "crypto/rsa"
	stdx509 "crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"

	trsa "github.com/blue-cloud-net/tongsuo-go/crypto/rsa"
)

// rsaKeyValue 为 .NET XML RSA 格式。
type rsaKeyValue struct {
	XMLName  xml.Name `xml:"RSAKeyValue"`
	Modulus  string   `xml:"Modulus"`
	Exponent string   `xml:"Exponent"`
	P        string   `xml:"P,omitempty"`
	Q        string   `xml:"Q,omitempty"`
	DP       string   `xml:"DP,omitempty"`
	DQ       string   `xml:"DQ,omitempty"`
	InverseQ string   `xml:"InverseQ,omitempty"`
	D        string   `xml:"D,omitempty"`
}

// MarshalPrivate 导出 RSA 私钥为 XML（含 D/P/Q/DP/DQ/InverseQ）。
func MarshalPrivate(priv *trsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("rsaxml: nil private key")
	}
	p := priv.Params()
	if p == nil || p.Type != "RSA" || p.N == nil || p.E == nil || p.D == nil {
		return nil, fmt.Errorf("rsaxml: not an RSA private key")
	}
	v := &rsaKeyValue{
		Modulus:  b64Std(p.N),
		Exponent: b64Std(p.E),
		D:        b64Std(p.D),
	}
	if p.P != nil && p.Q != nil {
		one := big.NewInt(1)
		pm1 := new(big.Int).Sub(p.P, one)
		qm1 := new(big.Int).Sub(p.Q, one)
		v.P = b64Std(p.P)
		v.Q = b64Std(p.Q)
		v.DP = b64Std(new(big.Int).Mod(p.D, pm1))
		v.DQ = b64Std(new(big.Int).Mod(p.D, qm1))
		v.InverseQ = b64Std(new(big.Int).ModInverse(p.Q, p.P))
	}
	return xml.MarshalIndent(v, "", "  ")
}

// MarshalPublic 导出 RSA 公钥为 XML（仅 Modulus + Exponent）。
func MarshalPublic(pub *trsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("rsaxml: nil public key")
	}
	p := pub.Params()
	if p == nil || p.Type != "RSA" || p.N == nil || p.E == nil {
		return nil, fmt.Errorf("rsaxml: not an RSA public key")
	}
	v := &rsaKeyValue{Modulus: b64Std(p.N), Exponent: b64Std(p.E)}
	return xml.MarshalIndent(v, "", "  ")
}

// UnmarshalPrivate 从 XML 解析 RSA 私钥。
func UnmarshalPrivate(data []byte) (*trsa.PrivateKey, error) {
	var v rsaKeyValue
	if err := xml.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("rsaxml: invalid XML: %w", err)
	}
	if v.Modulus == "" || v.Exponent == "" || v.D == "" {
		return nil, fmt.Errorf("rsaxml: missing Modulus/Exponent/D")
	}
	priv, err := toStdPrivate(&v)
	if err != nil {
		return nil, err
	}
	der := stdx509.MarshalPKCS1PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return trsa.LoadPrivateKeyPEM(pemBytes) // 自动识别 PKCS#1
}

// UnmarshalPublic 从 XML 解析 RSA 公钥。
func UnmarshalPublic(data []byte) (*trsa.PublicKey, error) {
	var v rsaKeyValue
	if err := xml.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("rsaxml: invalid XML: %w", err)
	}
	if v.Modulus == "" || v.Exponent == "" {
		return nil, fmt.Errorf("rsaxml: missing Modulus/Exponent")
	}
	n, err := unb64Std(v.Modulus)
	if err != nil {
		return nil, err
	}
	e, err := unb64Std(v.Exponent)
	if err != nil {
		return nil, err
	}
	pub := &stdrsa.PublicKey{N: n, E: int(e.Int64())}
	der, err := stdx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("rsaxml: marshal SPKI: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return trsa.LoadPublicKeyPEM(pemBytes)
}

// toStdPrivate 从 XML 值构造标准库 RSA 私钥。
func toStdPrivate(v *rsaKeyValue) (*stdrsa.PrivateKey, error) {
	n, err := unb64Std(v.Modulus)
	if err != nil {
		return nil, err
	}
	e, err := unb64Std(v.Exponent)
	if err != nil {
		return nil, err
	}
	d, err := unb64Std(v.D)
	if err != nil {
		return nil, err
	}
	priv := &stdrsa.PrivateKey{
		PublicKey: stdrsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
	}
	if v.P != "" && v.Q != "" {
		p, err1 := unb64Std(v.P)
		if err1 != nil {
			return nil, err1
		}
		q, err2 := unb64Std(v.Q)
		if err2 != nil {
			return nil, err2
		}
		priv.Primes = []*big.Int{p, q}
	}
	if err := priv.Validate(); err != nil {
		return nil, fmt.Errorf("rsaxml: invalid RSA key: %w", err)
	}
	priv.Precompute()
	return priv, nil
}

// b64Std 标准 base64 编码（含填充）。
func b64Std(n *big.Int) string {
	return base64.StdEncoding.EncodeToString(n.Bytes())
}

// unb64Std 标准 base64 解码。
func unb64Std(s string) (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("rsaxml: invalid base64: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}
