// Package x509 基于铜锁原生实现实现 X.509 证书与证书签名请求（CSR）管理。
//
// 支持证书的 PEM 加载/导出、主题/签发者/有效期/序列号/公钥读取、
// 证书创建与签名（自签或 CA 签发）、CSR 生成与验证。
package x509

import (
	"fmt"
	"strings"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Name 表示证书主题/签发者名字，支持链式构建。
type Name struct {
	name *core.Name
}

// NameEntry 表示名字中的一个 RDN 条目。
type NameEntry struct {
	Nid   int    // 字段 NID
	Field string // 字段短名，如 "CN"、"O"
	Value string // 字段值（UTF-8）
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

// Entries 返回名字的全部 RDN 条目（保持证书中的顺序）。
func (n *Name) Entries() []NameEntry {
	es := n.name.Entries()
	out := make([]NameEntry, 0, len(es))
	for _, e := range es {
		out = append(out, NameEntry{Nid: e.Nid, Field: e.Field, Value: e.Value})
	}
	return out
}

// Get 返回指定字段短名（如 "CN"、"O"）的值；未找到返回空串。
func (n *Name) Get(field string) string { return n.name.Get(field) }

// String 返回名字的完整单行文本（如 "/CN=example.com/O=Example Org"）。
func (n *Name) String() string { return n.name.String() }

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

// LoadCertificateDER 从 DER 编码加载证书。
func LoadCertificateDER(der []byte) (*Certificate, error) {
	c, err := core.LoadCertificateDER(der)
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

// Version 返回证书版本（0=v1，2=v3）。
func (c *Certificate) Version() int { return c.cert.Version() }

// SubjectName 返回主题的完整名字（含全部 RDN 条目，可配合 Entries/Get/String 使用）。
func (c *Certificate) SubjectName() *Name { return &Name{name: c.cert.SubjectName()} }

// IssuerName 返回签发者的完整名字（含全部 RDN 条目）。
func (c *Certificate) IssuerName() *Name { return &Name{name: c.cert.IssuerName()} }

// SubjectEntries 返回主题的完整 RDN 条目。
func (c *Certificate) SubjectEntries() []NameEntry {
	return convertEntries(c.cert.SubjectEntries())
}

// IssuerEntries 返回签发者的完整 RDN 条目。
func (c *Certificate) IssuerEntries() []NameEntry {
	return convertEntries(c.cert.IssuerEntries())
}

func convertEntries(es []core.NameEntry) []NameEntry {
	out := make([]NameEntry, 0, len(es))
	for _, e := range es {
		out = append(out, NameEntry{Nid: e.Nid, Field: e.Field, Value: e.Value})
	}
	return out
}

// SubjectText 返回主题完整 RDN 单行文本。
func (c *Certificate) SubjectText() string { return c.cert.SubjectText() }

// IssuerText 返回签发者完整 RDN 单行文本。
func (c *Certificate) IssuerText() string { return c.cert.IssuerText() }

// SAN 返回证书 SAN（subjectAltName）扩展条目（如 "DNS:example.com"、"IP:1.2.3.4"）；
// 无 SAN 扩展返回 nil。
func (c *Certificate) SAN() []string { return c.cert.SAN() }

// KeyUsage 返回证书 KeyUsage 能力位名称列表（如 ["digitalSignature"]）；无则 nil。
func (c *Certificate) KeyUsage() []string { return c.cert.KeyUsage() }

// ExtendedKeyUsage 返回证书 EKU 条目（如 ["serverAuth"]）；无则 nil。
func (c *Certificate) ExtendedKeyUsage() []string { return c.cert.ExtendedKeyUsage() }

// IsCA 报告证书是否为 CA（BasicConstraints.CA=TRUE）。
func (c *Certificate) IsCA() bool { return c.cert.IsCA() }

// PathLen 返回 CA 路径长度约束；无 pathlen 或非 CA 返回 -1。
func (c *Certificate) PathLen() int64 { return c.cert.PathLen() }

// SubjectKeyID 返回 subjectKeyIdentifier 扩展字节；无则 nil。
func (c *Certificate) SubjectKeyID() []byte { return c.cert.SubjectKeyID() }

// AuthorityKeyID 返回 authorityKeyIdentifier 中 keyid 字节；无则 nil。
func (c *Certificate) AuthorityKeyID() []byte { return c.cert.AuthorityKeyID() }

// CertificateType 返回证书公钥算法名（如 "SM2"、"RSA"、"EC"）。
func (c *Certificate) CertificateType() string { return c.cert.CertificateType() }

// Extension 表示证书/CSR 中的一个 X.509 扩展。
type Extension struct {
	Nid      int    // 扩展 NID
	Field    string // 扩展短名（读取时填充，如 "subjectAltName"）
	Critical bool   // critical 标志（读取时填充）
	Value    string // X509V3_EXT_conf 配置串（构建时使用，如 "DNS:example.com"）
	Data     []byte // DER 编码的扩展值（读取时填充）
}

// Extensions 返回证书的全部扩展（按出现顺序）。
func (c *Certificate) Extensions() []Extension { return convertExtensions(c.cert.Extensions()) }

func convertExtensions(es []core.Extension) []Extension {
	out := make([]Extension, 0, len(es))
	for _, e := range es {
		out = append(out, Extension{
			Nid:      e.Nid,
			Field:    e.Field,
			Critical: e.Critical,
			Value:    e.Value,
			Data:     e.Data,
		})
	}
	return out
}

// AddSubjectAltName 添加 SAN 扩展（如 "DNS:example.com,IP:1.2.3.4"；须在 Sign 之前调用）。
func (c *Certificate) AddSubjectAltName(value string) error {
	return c.cert.AddSubjectAltName(value)
}

// AddKeyUsage 添加 KeyUsage 扩展（如 "critical,digitalSignature,keyEncipherment"）。
func (c *Certificate) AddKeyUsage(value string) error {
	return c.cert.AddKeyUsage(value)
}

// AddExtendedKeyUsage 添加 EKU 扩展（如 "serverAuth,clientAuth"）。
func (c *Certificate) AddExtendedKeyUsage(value string) error {
	return c.cert.AddExtendedKeyUsage(value)
}

// AddSubjectKeyID 添加 SKID 扩展（按主题公钥自动计算）。
func (c *Certificate) AddSubjectKeyID() error {
	return c.cert.AddSubjectKeyID()
}

// AddAuthorityKeyID 添加 AKID 扩展（keyid 取自 issuer 证书的 SKID 或按 issuer 公钥计算）。
// 须在调用前为 issuer 完成公钥设置（推荐先对 issuer 调用 AddSubjectKeyID）。
func (c *Certificate) AddAuthorityKeyID(issuer *Certificate) error {
	if issuer == nil {
		return fmt.Errorf("x509: nil issuer certificate")
	}
	return c.cert.AddAuthorityKeyID(issuer.cert)
}

// Fingerprint 计算证书指纹（十六进制小写）。
// alg 支持 "sha1"、"sha256"、"sm3"、"md5"、"sha384"、"sha512"。
func (c *Certificate) Fingerprint(alg string) (string, error) {
	var md *core.Digest
	switch strings.ToLower(alg) {
	case "sha1":
		md = core.SHA1()
	case "sha256":
		md = core.SHA256()
	case "sm3":
		md = core.SM3()
	case "md5":
		md = core.MD5()
	case "sha384":
		md = core.SHA384()
	case "sha512":
		md = core.SHA512()
	default:
		return "", fmt.Errorf("x509: unsupported fingerprint algorithm %q", alg)
	}
	return c.cert.Fingerprint(md)
}

// MarshalDER 导出证书为 DER 编码。
func (c *Certificate) MarshalDER() ([]byte, error) {
	return c.cert.MarshalDER()
}

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

// NewEmptyCertificateRequest 创建空 CSR（构建用）。
// 通过 SetSubject / SetPublicKey / SetChallengePassword / AddExtensions 配置后调用 Sign 完成签名；
// NewCertificateRequest 是一次性便捷版（立即签名）。
func NewEmptyCertificateRequest() *CertificateRequest {
	r, err := core.NewCertificateRequest()
	if err != nil {
		panic(err)
	}
	return &CertificateRequest{req: r}
}

// SetSubject 设置 CSR 主题。
func (r *CertificateRequest) SetSubject(n *Name) error {
	if n == nil {
		return fmt.Errorf("x509: nil subject name")
	}
	return r.req.SetSubject(n.name)
}

// SetPublicKey 设置 CSR 公钥。
func (r *CertificateRequest) SetPublicKey(pub *sm2.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("x509: nil public key")
	}
	return r.req.SetPublicKey(pub.Key())
}

// Sign 使用请求者私钥对 CSR 签名（须先配置好主题/公钥/扩展/口令）。
func (r *CertificateRequest) Sign(priv *sm2.PrivateKey) error {
	if priv == nil {
		return fmt.Errorf("x509: nil private key")
	}
	return r.req.Sign(priv.Key(), core.SM3())
}

// LoadCertificateRequestPEM 从 PEM 加载 CSR。
func LoadCertificateRequestPEM(pem []byte) (*CertificateRequest, error) {
	r, err := core.LoadCertificateRequestPEM(pem)
	if err != nil {
		return nil, err
	}
	return &CertificateRequest{req: r}, nil
}

// LoadCertificateRequestDER 从 DER 编码加载 CSR。
func LoadCertificateRequestDER(der []byte) (*CertificateRequest, error) {
	r, err := core.LoadCertificateRequestDER(der)
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

// SubjectName 返回 CSR 主题的完整名字（含全部 RDN 条目）。
func (r *CertificateRequest) SubjectName() *Name {
	return &Name{name: r.req.SubjectName()}
}

// SetChallengePassword 设置 CSR 挑战密码（PKCS#9 challengePassword 属性，须在 Sign 之前调用）。
func (r *CertificateRequest) SetChallengePassword(pwd string) error {
	return r.req.SetChallengePassword(pwd)
}

// ChallengePassword 返回 CSR 挑战密码；未设置返回空串。
func (r *CertificateRequest) ChallengePassword() string {
	return r.req.ChallengePassword()
}

// AddExtensions 为 CSR 添加多个扩展（如 SAN / KeyUsage / EKU，须在 Sign 之前调用）。
func (r *CertificateRequest) AddExtensions(exts ...Extension) error {
	cexts := make([]core.Extension, 0, len(exts))
	for _, e := range exts {
		cexts = append(cexts, core.Extension{Nid: e.Nid, Value: e.Value})
	}
	return r.req.AddExtensions(cexts...)
}

// AddExtension 为 CSR 添加单个扩展（如 "subjectAltName"，须在 Sign 之前调用）。
func (r *CertificateRequest) AddExtension(nid int, value string) error {
	return r.req.AddExtension(nid, value)
}

// AddSubjectAltName 为 CSR 添加 SAN 扩展（如 "DNS:example.com"）。
func (r *CertificateRequest) AddSubjectAltName(value string) error {
	return r.req.AddSubjectAltName(value)
}

// Extensions 返回 CSR 中的扩展列表（来自 extensionRequest 属性）。
func (r *CertificateRequest) Extensions() []Extension {
	return convertExtensions(r.req.Extensions())
}

// MarshalDER 导出 CSR 为 DER 编码。
func (r *CertificateRequest) MarshalDER() ([]byte, error) {
	return r.req.MarshalDER()
}
