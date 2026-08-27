// Package x509 基于铜锁原生实现实现 X.509 证书与证书签名请求（CSR）管理。
//
// 支持证书的 PEM 加载/导出、主题/签发者/有效期/序列号/公钥读取、
// 证书创建与签名（自签或 CA 签发）、CSR 生成与验证。
package x509

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Name 表示证书主题/签发者名字，支持链式构建。
type Name struct {
	name *core.Name
}

// NewName 创建空名字。
func NewName() *Name {
	n, err := core.NewName()
	if err != nil {
		panic(err)
	}
	return &Name{name: n}
}

// Add 添加名字字段并返回自身（链式）。
// field 取 "CN"、"C"、"O"、"OU"、"L"、"ST"、"serialNumber"、"emailAddress" 等。
func (n *Name) Add(field, value string) *Name {
	if err := n.name.AddEntry(field, value); err != nil {
		panic(err)
	}
	return n
}

// Certificate 表示一张 X.509 证书。
type Certificate struct {
	cert *core.Certificate
}

// Core 返回底层核心证书对象（供内部跨包使用，如 tls）。
func (c *Certificate) Core() *core.Certificate { return c.cert }

// LoadCertificatePEM 从 PEM 加载证书。
func LoadCertificatePEM(pem []byte) (*Certificate, error) {
	c, err := core.LoadCertificatePEM(pem)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: c}, nil
}

// MarshalPEM 导出证书为 PEM。
func (c *Certificate) MarshalPEM() ([]byte, error) {
	return c.cert.MarshalPEM()
}

// Subject 返回主题的 CN（Common Name）。
func (c *Certificate) Subject() string { return c.cert.Subject() }

// Issuer 返回签发者的 CN（Common Name）。
func (c *Certificate) Issuer() string { return c.cert.Issuer() }

// NotBefore 返回生效时间。
func (c *Certificate) NotBefore() time.Time { return c.cert.NotBefore() }

// NotAfter 返回过期时间。
func (c *Certificate) NotAfter() time.Time { return c.cert.NotAfter() }

// Serial 返回证书序列号。
func (c *Certificate) Serial() int64 { return c.cert.Serial() }

// NewCertificate 创建一个空证书（构建用）。
// 通过 Set* 方法配置字段后调用 Sign 完成签名；CreateCertificate 是一次性便捷版。
func NewCertificate() *Certificate {
	cert, err := core.NewCertificate()
	if err != nil {
		panic(err)
	}
	return &Certificate{cert: cert}
}

// SetVersion 设置证书版本（0=v1，2=v3）。
func (c *Certificate) SetVersion(v int) error { return c.cert.SetVersion(v) }

// SetSerial 设置证书序列号。
func (c *Certificate) SetSerial(serial int64) error { return c.cert.SetSerial(serial) }

// SetIssuer 设置签发者名字。
func (c *Certificate) SetIssuer(n *Name) error { return c.cert.SetIssuer(n.name) }

// SetSubject 设置主题名字。
func (c *Certificate) SetSubject(n *Name) error { return c.cert.SetSubject(n.name) }

// SetValidity 设置有效期。
func (c *Certificate) SetValidity(notBefore, notAfter time.Time) error {
	return c.cert.SetValidity(notBefore, notAfter)
}

// SetPublicKey 设置证书公钥。
func (c *Certificate) SetPublicKey(pub *sm2.PublicKey) error {
	return c.cert.SetPublicKey(pub.Key())
}

// AddBasicConstraints 添加 BasicConstraints 扩展（必须在 Sign 之前调用）。
func (c *Certificate) AddBasicConstraints(isCA bool) error {
	return c.cert.AddBasicConstraints(isCA)
}

// Sign 使用签名私钥对证书签名（须先配置好版本/序列号/主题/签发者/有效期/公钥/扩展）。
func (c *Certificate) Sign(signer *sm2.PrivateKey) error {
	return c.cert.Sign(signer.Key(), core.SM3())
}

// PublicKey 返回证书公钥（SM2）。
func (c *Certificate) PublicKey() (*sm2.PublicKey, error) {
	k, err := c.cert.PublicKey()
	if err != nil {
		return nil, err
	}
	return sm2.PublicKeyFromPKey(k), nil
}

// Verify 使用签发者公钥验证证书签名。
func (c *Certificate) Verify(signerPub *sm2.PublicKey) error {
	return c.cert.Verify(signerPub.Key())
}

// CreateCertificate 创建一张由 signer 签发的证书。
// subject 为主题；issuer 为签发者（自签时与 subject 相同）；serial 为序列号；
// notBefore/notAfter 为有效期；pub 为证书公钥；signer 为签发私钥
// （自签时与 pub 对应，CA 签发时为 CA 私钥）。
func CreateCertificate(subject, issuer *Name, serial int64, notBefore, notAfter time.Time,
	pub *sm2.PublicKey, signer *sm2.PrivateKey) (*Certificate, error) {
	if subject == nil || issuer == nil || pub == nil || signer == nil {
		return nil, fmt.Errorf("x509: nil parameter")
	}
	cert, err := core.NewCertificate()
	if err != nil {
		return nil, err
	}
	if err := cert.SetVersion(2); err != nil { // v3
		return nil, err
	}
	if err := cert.SetSerial(serial); err != nil {
		return nil, err
	}
	if err := cert.SetIssuer(issuer.name); err != nil {
		return nil, err
	}
	if err := cert.SetSubject(subject.name); err != nil {
		return nil, err
	}
	if err := cert.SetValidity(notBefore, notAfter); err != nil {
		return nil, err
	}
	if err := cert.SetPublicKey(pub.Key()); err != nil {
		return nil, err
	}
	if err := cert.Sign(signer.Key(), core.SM3()); err != nil {
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}

// CertificateRequest 表示一个证书签名请求。
type CertificateRequest struct {
	req *core.CertificateRequest
}

// NewCertificateRequest 创建 CSR 并签名。
// subject 为主题；pub 为请求者公钥；priv 为请求者私钥（用于签名）。
func NewCertificateRequest(subject *Name, pub *sm2.PublicKey, priv *sm2.PrivateKey) (*CertificateRequest, error) {
	if subject == nil || pub == nil || priv == nil {
		return nil, fmt.Errorf("x509: nil parameter")
	}
	req, err := core.NewCertificateRequest()
	if err != nil {
		return nil, err
	}
	if err := req.SetSubject(subject.name); err != nil {
		return nil, err
	}
	if err := req.SetPublicKey(pub.Key()); err != nil {
		return nil, err
	}
	if err := req.Sign(priv.Key(), core.SM3()); err != nil {
		return nil, err
	}
	return &CertificateRequest{req: req}, nil
}

// LoadCertificateRequestPEM 从 PEM 加载 CSR。
func LoadCertificateRequestPEM(pem []byte) (*CertificateRequest, error) {
	r, err := core.LoadCertificateRequestPEM(pem)
	if err != nil {
		return nil, err
	}
	return &CertificateRequest{req: r}, nil
}

// MarshalPEM 导出 CSR 为 PEM。
func (r *CertificateRequest) MarshalPEM() ([]byte, error) {
	return r.req.MarshalPEM()
}

// Verify 使用 CSR 自身公钥验证签名。
func (r *CertificateRequest) Verify() error {
	return r.req.Verify()
}

// PublicKey 返回 CSR 公钥（SM2）。
func (r *CertificateRequest) PublicKey() (*sm2.PublicKey, error) {
	k, err := r.req.PublicKey()
	if err != nil {
		return nil, err
	}
	return sm2.PublicKeyFromPKey(k), nil
}
