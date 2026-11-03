package x509

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// LoadTrustedCertificatePEM 读取普通或 TRUSTED CERTIFICATE PEM，保留本地信任属性。
// 返回证书由调用方负责 Close；失败返回错误。
//
// LoadTrustedCertificatePEM reads ordinary or TRUSTED CERTIFICATE PEM, preserving local trust attributes.
// Callers must Close the returned certificate; failures return errors.
func LoadTrustedCertificatePEM(data []byte) (*Certificate, error) {
	c, err := core.LoadTrustedCertificatePEM(data)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: c}, nil
}

// AddTrust 添加信任用途属性；属性不属于签名内容，可在签名后修改。
// 用途接受 OpenSSL 名称（如 serverAuth）或点分 OID；nil 或已关闭证书返回错误。
//
// AddTrust adds trusted purposes outside the signed certificate; it is allowed after signing.
// Purposes accept OpenSSL names (such as serverAuth) or dotted OIDs; nil or closed certificates return errors.
func (c *Certificate) AddTrust(purpose string) error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return c.cert.AddTrust(purpose, false)
}

// AddReject 添加拒绝用途属性；属性不属于签名内容，可在签名后修改。
// 用途接受 OpenSSL 名称（如 serverAuth）或点分 OID；nil 或已关闭证书返回错误。
//
// AddReject adds rejected purposes outside the signed certificate; it is allowed after signing.
// Purposes accept OpenSSL names (such as serverAuth) or dotted OIDs; nil or closed certificates return errors.
func (c *Certificate) AddReject(purpose string) error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return c.cert.AddTrust(purpose, true)
}

// ClearTrust 清空信任用途属性；属性不属于签名内容，可在签名后修改。
// nil 或已关闭证书返回错误。
//
// ClearTrust clears trusted purposes outside the signed certificate; it is allowed after signing.
// nil or closed certificates return errors.
func (c *Certificate) ClearTrust() error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return c.cert.ClearTrust(false)
}

// ClearReject 清空拒绝用途属性；属性不属于签名内容，可在签名后修改。
// nil 或已关闭证书返回错误。
//
// ClearReject clears rejected purposes outside the signed certificate; it is allowed after signing.
// nil or closed certificates return errors.
func (c *Certificate) ClearReject() error {
	if c == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	return c.cert.ClearTrust(true)
}

// MarshalTrustedPEM 导出带本地信任属性的 PEM；普通 MarshalPEM/DER 不包含这些属性。
// nil 或已关闭证书返回错误。
//
// MarshalTrustedPEM exports PEM including local trust attributes; ordinary MarshalPEM/DER omit them.
// Nil or closed certificates return errors.
func (c *Certificate) MarshalTrustedPEM() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("x509: nil certificate")
	}
	return c.cert.MarshalTrustedPEM()
}
