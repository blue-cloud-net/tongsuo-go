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

// Signature 返回 CRL 的原始签名字节（DER 编码）；CRL 无效或未签名返回 nil。
//
// Signature returns the CRL's raw signature bytes (DER-encoded), or nil when the CRL is invalid or has no signature.
func (c *CRL) Signature() []byte { return c.crl.Signature() }

// SignatureAlgorithm 返回 CRL 签名算法的短名（如 "SM2-SM3"、"RSA-SHA256"、"ecdsa-with-SHA256"）；不可识别返回 ""。
//
// SignatureAlgorithm returns the signature algorithm short name (for example "SM2-SM3", "RSA-SHA256", or "ecdsa-with-SHA256"), or "" when the algorithm is not recognized.
func (c *CRL) SignatureAlgorithm() string { return c.crl.SignatureAlgorithm() }

// SignatureAlgorithmOID 返回 CRL 签名算法的 OID 点分文本（如 "1.2.156.10197.1.501"、"1.2.840.113549.1.1.11"）；不可读取返回 ""。
//
// SignatureAlgorithmOID returns the signature algorithm OID as a dotted string (for example "1.2.156.10197.1.501" for SM2-with-SM3 or "1.2.840.113549.1.1.11" for sha256WithRSAEncryption), or "" when the OID cannot be read.
func (c *CRL) SignatureAlgorithmOID() string { return c.crl.SignatureAlgorithmOID() }

// AuthorityKeyID 返回 authorityKeyIdentifier 扩展中 keyid 的字节；无则返回 nil。
//
// AuthorityKeyID returns the keyid bytes of the authorityKeyIdentifier extension, or nil when the extension is absent.
func (c *CRL) AuthorityKeyID() []byte { return c.crl.AuthorityKeyID() }

// Number 返回 CRL Number 扩展的整数值；无 CRL Number 扩展或无效返回 -1。
//
// Number returns the integer value of the CRL Number extension, or -1 when no CRL Number extension is present.
func (c *CRL) Number() int64 { return c.crl.Number() }

// Extensions 返回 CRL 中的全部扩展（按出现顺序）。
//
// Extensions returns every extension of the CRL in the order they appear.
func (c *CRL) Extensions() []Extension { return convertExtensions(c.crl.Extensions()) }

// IssuerEntries 返回签发者的完整 RDN 条目。
//
// IssuerEntries returns every RDN entry of the issuer in the order they appear in the CRL.
func (c *CRL) IssuerEntries() []NameEntry {
	n := c.crl.Issuer()
	if n == nil {
		return nil
	}
	return convertEntries(n.Entries())
}

// IssuerText 返回签发者完整 RDN 单行文本。
//
// IssuerText returns the issuer's full RDN sequence as a single-line string.
func (c *CRL) IssuerText() string {
	n := c.crl.Issuer()
	if n == nil {
		return ""
	}
	return n.String()
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

// Close 释放底层 X509_CRL 句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的 CRL 调用返回 nil，不产生副作用。
//
// Close releases the underlying X509_CRL handle.
//
// The call is idempotent: invoking it on a nil receiver or on a CRL
// that has already been closed returns nil without further side effects.
func (c *CRL) Close() error {
	if c == nil || c.crl == nil {
		return nil
	}
	return c.crl.Close()
}

// AddAuthorityKeyID 向 CRL 追加 authorityKeyIdentifier 扩展（keyid 取自 issuer 的 SKID 或公钥）。
// 须在 MarshalPEM / MarshalDER 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddAuthorityKeyID appends an authorityKeyIdentifier extension to the CRL.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *CRL) AddAuthorityKeyID(issuer *Certificate) error {
	if c == nil || c.crl == nil {
		return fmt.Errorf("x509: nil CRL")
	}
	if issuer == nil {
		return fmt.Errorf("x509: nil issuer certificate")
	}
	return c.crl.AddAuthorityKeyID(issuer.cert)
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
