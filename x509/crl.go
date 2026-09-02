package x509

import (
	"bytes"
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// RevokedEntry 表示 CRL 中的一条吊销记录。
//
// Serial 为被吊销证书的序列号；RevocationDate 为吊销生效时间；
// ReasonCode 为原因码（-1 表示未指定）；Reason 为人类可读的原因名（如 "keyCompromise"）。
//
// RevokedEntry represents a single revoked-certificate entry inside a CRL.
//
// Serial is the revoked certificate's serial number, RevocationDate is when
// the revocation became effective, ReasonCode is the numeric reason code
// (-1 means unspecified), and Reason is the human-readable reason name
// (for example "keyCompromise").
type RevokedEntry struct {
	Serial         int64     // 被吊销证书的序列号
	RevocationDate time.Time // 吊销时间
	ReasonCode     int       // 原因码（-1 表示未指定）
	Reason         string    // 原因名（如 "keyCompromise"）
}

// CRL 表示证书吊销列表。
//
// CRL represents an X.509 certificate revocation list.
type CRL struct {
	crl *core.CRL
}

// ParseCRL 从 PEM 或 DER 解析 CRL（自动识别格式）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// ParseCRL parses CRL data in either PEM or DER form (the format is detected automatically) and returns a *CRL.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func ParseCRL(data []byte) (*CRL, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("x509: empty CRL data")
	}
	var c *core.CRL
	var err error
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		c, err = core.LoadCRLPEM(data)
	} else {
		c, err = core.LoadCRLDER(data)
	}
	if err != nil {
		return nil, err
	}
	return &CRL{crl: c}, nil
}

// LoadCRLPEM 从 PEM 加载 CRL。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// LoadCRLPEM parses a PEM-encoded CRL and returns a *CRL.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func LoadCRLPEM(pemBytes []byte) (*CRL, error) {
	c, err := core.LoadCRLPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &CRL{crl: c}, nil
}

// LoadCRLDER 从 DER 加载 CRL。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// LoadCRLDER parses a DER-encoded CRL and returns a *CRL.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func LoadCRLDER(der []byte) (*CRL, error) {
	c, err := core.LoadCRLDER(der)
	if err != nil {
		return nil, err
	}
	return &CRL{crl: c}, nil
}

// MarshalPEM 导出 CRL 为 PEM。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// MarshalPEM encodes the CRL in PEM format.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *CRL) MarshalPEM() ([]byte, error) {
	return c.crl.MarshalPEM()
}

// MarshalDER 导出 CRL 为 DER。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// MarshalDER encodes the CRL in DER format.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *CRL) MarshalDER() ([]byte, error) {
	return c.crl.MarshalDER()
}

// Issuer 返回 CRL 签发者完整名字（含全部 RDN 条目）。
//
// Issuer returns the full issuer name of the CRL containing all RDN entries; inspect it with Entries, Get, or String.
func (c *CRL) Issuer() *Name {
	return &Name{name: c.crl.Issuer()}
}

// Version 返回 CRL 版本字段值（0=v1，1=v2）。
//
// Version returns the CRL version field (0 = v1, 1 = v2).
func (c *CRL) Version() int {
	return c.crl.Version()
}

// LastUpdate 返回 CRL 生效时间。
//
// LastUpdate returns the CRL's thisUpdate time.
func (c *CRL) LastUpdate() time.Time {
	return c.crl.LastUpdate()
}

// NextUpdate 返回 CRL 过期时间。
//
// NextUpdate returns the CRL's nextUpdate time.
func (c *CRL) NextUpdate() time.Time {
	return c.crl.NextUpdate()
}

// RevokedEntries 返回 CRL 中的全部吊销记录。
//
// RevokedEntries returns every revoked-certificate entry contained in the CRL.
func (c *CRL) RevokedEntries() []RevokedEntry {
	es := c.crl.RevokedEntries()
	out := make([]RevokedEntry, 0, len(es))
	for _, e := range es {
		out = append(out, RevokedEntry{
			Serial:         e.Serial,
			RevocationDate: e.RevocationDate,
			ReasonCode:     e.ReasonCode,
			Reason:         e.Reason,
		})
	}
	return out
}

// IsRevoked 报告证书是否在此 CRL 中被吊销（仅按序列号匹配）。
//
// IsRevoked reports whether cert is revoked by this CRL. Matching is performed by serial number only.
func (c *CRL) IsRevoked(cert *Certificate) bool {
	if cert == nil {
		return false
	}
	serial := cert.Serial()
	for _, e := range c.RevokedEntries() {
		if e.Serial == serial {
			return true
		}
	}
	return false
}

// RevocationCheck 检查证书是否被任一 CRL 吊销。
// 仅当 CRL 的签发者与证书签发者一致且序列号匹配时判定为已吊销。
// 未吊销返回 nil；已吊销返回描述性错误。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// RevocationCheck reports whether cert is revoked by any of the supplied CRLs. A CRL is only considered when its issuer matches the certificate's issuer and the serial number matches; an unrevoked certificate yields nil, while a revoked one produces a descriptive error.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func RevocationCheck(cert *Certificate, crls []*CRL) error {
	if cert == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	ccrls := make([]*core.CRL, 0, len(crls))
	for _, c := range crls {
		if c == nil {
			continue
		}
		ccrls = append(ccrls, c.crl)
	}
	return core.RevocationCheck(cert.cert, ccrls)
}
