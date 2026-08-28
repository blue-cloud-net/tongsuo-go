// Package pkcs12 基于铜锁原生实现实现 PKCS#12 容器（.p12 / .pfx）。
//
// 提供打包（证书 + 私钥 + CA 链 + 口令）、解析与改密。输入输出均为 DER 编码，
// 与 `openssl pkcs12` 互通。
package pkcs12

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/crypto/x509"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// PrivateKey 表示可打包进 PKCS#12 的私钥（sm2 / rsa / ecdsa 的 PrivateKey 均实现）。
type PrivateKey = x509.PrivateKey

// Bundle 表示解析后的 PKCS#12 内容。
type Bundle struct {
	PrivateKey  *core.PKey          // 私钥（调用方负责 Close）
	Certificate *x509.Certificate   // 主证书
	CACerts     []*x509.Certificate // CA 链
}

// Pack 将证书、私钥与 CA 链打包为 PKCS#12（DER）。
// password 为口令；name 为友好名称（可空）。
func Pack(cert *x509.Certificate, key PrivateKey, ca []*x509.Certificate, password, name string) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("pkcs12: nil certificate")
	}
	if key == nil {
		return nil, fmt.Errorf("pkcs12: nil private key")
	}
	ccerts := make([]*core.Certificate, 0, len(ca))
	for _, c := range ca {
		if c != nil {
			ccerts = append(ccerts, c.Core())
		}
	}
	p12, err := core.CreatePKCS12(password, name, key.Key(), cert.Core(), ccerts)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	return p12.MarshalDER()
}

// Parse 从 DER 解析 PKCS#12。
func Parse(data []byte, password string) (*Bundle, error) {
	p12, err := core.LoadPKCS12DER(data)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	key, cert, ca, err := p12.Parse(password)
	if err != nil {
		return nil, err
	}
	b := &Bundle{PrivateKey: key}
	if cert != nil {
		b.Certificate = x509.WrapCertificate(cert)
	}
	for _, c := range ca {
		b.CACerts = append(b.CACerts, x509.WrapCertificate(c))
	}
	return b, nil
}

// ChangePassword 修改 PKCS#12 口令（输入输出均为 DER）。
func ChangePassword(data []byte, oldPass, newPass string) ([]byte, error) {
	p12, err := core.LoadPKCS12DER(data)
	if err != nil {
		return nil, err
	}
	defer p12.Close()
	if err := p12.ChangePassword(oldPass, newPass); err != nil {
		return nil, err
	}
	return p12.MarshalDER()
}
