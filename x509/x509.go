// Package x509 基于铜锁原生实现实现 X.509 证书与证书签名请求（CSR）管理。
//
// 支持证书的 PEM 加载/导出、主题/签发者/有效期/序列号/公钥读取、
// 证书创建与签名（自签或 CA 签发）、CSR 生成与验证。
//
// 内部按职责拆分为多个文件：
//
//	x509.go    — Certificate 主类型、Extension 类型、PublicKey/PrivateKey 接口、
//	             CreateCertificate、Set* 构建方法、Add* 扩展方法、签/验
//	name.go    — Name / NameEntry / NewName
//	csr.go     — CertificateRequest（含 New/NewEmptyCertificateRequest 与所有 CSR 方法）
//	store.go   — Store / VerifyError / NewStore / ChainVerify
//	crl.go     — CRL / RevokedEntry / ParseCRL / RevocationCheck
//	helpers.go — convertEntries / convertExtensions（内部转换辅助）
//
// Package x509 provides X.509 certificate and certificate signing request
// (CSR) management built on the Tongsuo native library.
//
// It covers PEM loading and export of certificates, reading of subject /
// issuer / validity / serial number / public key, certificate creation and
// signing (self-signed or CA-issued), and CSR generation and verification.
//
// The package is split across files by responsibility:
//
//	x509.go    — Certificate main type, Extension type, PublicKey /
//	             PrivateKey interfaces, CreateCertificate, Set* builders,
//	             Add* extension methods, sign / verify
//	name.go    — Name / NameEntry / NewName
//	csr.go     — CertificateRequest (New / NewEmptyCertificateRequest and
//	             all CSR methods)
//	store.go   — Store / VerifyError / NewStore / ChainVerify
//	crl.go     — CRL / RevokedEntry / ParseCRL / RevocationCheck
//	helpers.go — convertEntries / convertExtensions (internal helpers)
package x509

import (
	"fmt"
	"strings"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Certificate 表示一张 X.509 证书。
//
// Certificate represents an X.509 certificate.
type Certificate struct {
	cert *core.Certificate
}

// Core 返回底层核心证书对象（供内部跨包使用，如 tls）。
//
// Core returns the underlying core.Certificate for cross-package use (for example by the tls package).
func (c *Certificate) Core() *core.Certificate { return c.cert }

// LoadCertificatePEM 从 PEM 加载证书。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// LoadCertificatePEM parses PEM-encoded certificate data and returns a *Certificate.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func LoadCertificatePEM(pemBytes []byte) (*Certificate, error) {
	c, err := core.LoadCertificatePEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: c}, nil
}

// LoadCertificateDER 从 DER 编码加载证书。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// LoadCertificateDER parses DER-encoded certificate data and returns a *Certificate.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func LoadCertificateDER(der []byte) (*Certificate, error) {
	c, err := core.LoadCertificateDER(der)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert: c}, nil
}

// WrapCertificate 用底层核心证书构造 Certificate（供内部跨包使用，如 pkcs/pkcs12、pkcs/pkcs7）。
//
// WrapCertificate wraps an underlying *core.Certificate into the API-layer Certificate type for cross-package use (for example by pkcs/pkcs12 and pkcs/pkcs7).
func WrapCertificate(c *core.Certificate) *Certificate {
	return &Certificate{cert: c}
}

// MarshalPEM 导出证书为 PEM。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// MarshalPEM encodes the certificate in PEM format.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) MarshalPEM() ([]byte, error) {
	return c.cert.MarshalPEM()
}

// Subject 返回主题的 CN（Common Name）。
//
// Subject returns the Common Name (CN) of the certificate subject.
func (c *Certificate) Subject() string { return c.cert.Subject() }

// Issuer 返回签发者的 CN（Common Name）。
//
// Issuer returns the Common Name (CN) of the certificate issuer.
func (c *Certificate) Issuer() string { return c.cert.Issuer() }

// NotBefore 返回生效时间。
//
// NotBefore returns the certificate's activation time.
func (c *Certificate) NotBefore() time.Time { return c.cert.NotBefore() }

// NotAfter 返回过期时间。
//
// NotAfter returns the certificate's expiration time.
func (c *Certificate) NotAfter() time.Time { return c.cert.NotAfter() }

// Serial 返回证书序列号。
//
// Serial returns the certificate's serial number.
func (c *Certificate) Serial() int64 { return c.cert.Serial() }

// Version 返回证书版本（0=v1，2=v3）。
//
// Version returns the certificate version field (0 = v1, 2 = v3).
func (c *Certificate) Version() int { return c.cert.Version() }

// SubjectName 返回主题的完整名字（含全部 RDN 条目，可配合 Entries/Get/String 使用）。
//
// SubjectName returns the full subject name containing all RDN entries; inspect it with Entries, Get, or String.
func (c *Certificate) SubjectName() *Name { return &Name{name: c.cert.SubjectName()} }

// IssuerName 返回签发者的完整名字（含全部 RDN 条目）。
//
// IssuerName returns the full issuer name containing all RDN entries; inspect it with Entries, Get, or String.
func (c *Certificate) IssuerName() *Name { return &Name{name: c.cert.IssuerName()} }

// SubjectEntries 返回主题的完整 RDN 条目。
//
// SubjectEntries returns every RDN entry of the subject in the order they appear in the certificate.
func (c *Certificate) SubjectEntries() []NameEntry {
	return convertEntries(c.cert.SubjectEntries())
}

// IssuerEntries 返回签发者的完整 RDN 条目。
//
// IssuerEntries returns every RDN entry of the issuer in the order they appear in the certificate.
func (c *Certificate) IssuerEntries() []NameEntry {
	return convertEntries(c.cert.IssuerEntries())
}

// SubjectText 返回主题完整 RDN 单行文本。
//
// SubjectText returns the subject's full RDN sequence as a single-line string.
func (c *Certificate) SubjectText() string { return c.cert.SubjectText() }

// IssuerText 返回签发者完整 RDN 单行文本。
//
// IssuerText returns the issuer's full RDN sequence as a single-line string.
func (c *Certificate) IssuerText() string { return c.cert.IssuerText() }

// SAN 返回证书 SAN（subjectAltName）扩展条目（如 "DNS:example.com"、"IP:1.2.3.4"）；
// 无 SAN 扩展返回 nil。
//
// SAN returns the certificate's subjectAltName entries (for example "DNS:example.com", "IP:1.2.3.4"). It returns nil when no SAN extension is present.
func (c *Certificate) SAN() []string { return c.cert.SAN() }

// KeyUsage 返回证书 KeyUsage 能力位名称列表（如 ["digitalSignature"]）；无则 nil。
//
// KeyUsage returns the certificate's KeyUsage bit names (for example ["digitalSignature"]). It returns nil when no KeyUsage extension is present.
func (c *Certificate) KeyUsage() []string { return c.cert.KeyUsage() }

// ExtendedKeyUsage 返回证书 EKU 条目（如 ["serverAuth"]）；无则 nil。
//
// ExtendedKeyUsage returns the certificate's ExtendedKeyUsage entries (for example ["serverAuth"]). It returns nil when no EKU extension is present.
func (c *Certificate) ExtendedKeyUsage() []string { return c.cert.ExtendedKeyUsage() }

// IsCA 报告证书是否为 CA（BasicConstraints.CA=TRUE）。
//
// IsCA reports whether the certificate is a CA per BasicConstraints.CA = TRUE.
func (c *Certificate) IsCA() bool { return c.cert.IsCA() }

// PathLen 返回 CA 路径长度约束；无 pathlen 或非 CA 返回 -1。
//
// PathLen returns the CA path-length constraint, or -1 when pathlen is absent or the certificate is not a CA.
func (c *Certificate) PathLen() int64 { return c.cert.PathLen() }

// SubjectKeyID 返回 subjectKeyIdentifier 扩展字节；无则 nil。
//
// SubjectKeyID returns the bytes of the subjectKeyIdentifier extension, or nil when the extension is absent.
func (c *Certificate) SubjectKeyID() []byte { return c.cert.SubjectKeyID() }

// AuthorityKeyID 返回 authorityKeyIdentifier 中 keyid 字节；无则 nil。
//
// AuthorityKeyID returns the keyid bytes of the authorityKeyIdentifier extension, or nil when the extension is absent.
func (c *Certificate) AuthorityKeyID() []byte { return c.cert.AuthorityKeyID() }

// CertificateType 返回证书公钥算法名（如 "SM2"、"RSA"、"EC"）。
//
// CertificateType returns the algorithm name of the certificate's public key (for example "SM2", "RSA", "EC").
func (c *Certificate) CertificateType() string { return c.cert.CertificateType() }

// Extension 表示证书/CSR 中的一个 X.509 扩展。
//
// Nid 为扩展 NID；Field 与 Critical 在读取时填充；
// Value 为构建时使用的 X509V3_EXT_conf 配置串；
// Data 为 DER 编码的扩展值（读取时填充）。
//
// Extension represents a single X.509 extension on a certificate or CSR.
//
// Nid is the extension NID. Field and Critical are populated on read.
// Value holds an X509V3_EXT_conf configuration string used while building.
// Data holds the DER-encoded extension value (populated on read).
type Extension struct {
	Nid      int    // 扩展 NID
	Field    string // 扩展短名（读取时填充，如 "subjectAltName"）
	Critical bool   // critical 标志（读取时填充）
	Value    string // X509V3_EXT_conf 配置串（构建时使用，如 "DNS:example.com"）
	Data     []byte // DER 编码的扩展值（读取时填充）
}

// Extensions 返回证书的全部扩展（按出现顺序）。
//
// Extensions returns all certificate extensions in the order they appear.
func (c *Certificate) Extensions() []Extension { return convertExtensions(c.cert.Extensions()) }

// AddSubjectAltName 添加 SAN 扩展（如 "DNS:example.com,IP:1.2.3.4"；须在 Sign 之前调用）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddSubjectAltName appends a subjectAltName extension (for example "DNS:example.com,IP:1.2.3.4"). It must be called before Sign.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddSubjectAltName(value string) error {
	return c.cert.AddSubjectAltName(value)
}

// AddKeyUsage 添加 KeyUsage 扩展（如 "critical,digitalSignature,keyEncipherment"）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddKeyUsage appends a KeyUsage extension (for example "critical,digitalSignature,keyEncipherment").
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddKeyUsage(value string) error {
	return c.cert.AddKeyUsage(value)
}

// AddExtendedKeyUsage 添加 EKU 扩展（如 "serverAuth,clientAuth"）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddExtendedKeyUsage appends an ExtendedKeyUsage extension (for example "serverAuth,clientAuth").
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddExtendedKeyUsage(value string) error {
	return c.cert.AddExtendedKeyUsage(value)
}

// AddSubjectKeyID 添加 SKID 扩展（按主题公钥自动计算）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddSubjectKeyID appends a SubjectKeyIdentifier extension computed automatically from the subject's public key.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddSubjectKeyID() error {
	return c.cert.AddSubjectKeyID()
}

// AddAuthorityKeyID 添加 AKID 扩展（keyid 取自 issuer 证书的 SKID 或按 issuer 公钥计算）。
// 须在调用前为 issuer 完成公钥设置（推荐先对 issuer 调用 AddSubjectKeyID）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddAuthorityKeyID appends an AuthorityKeyIdentifier extension. The keyid is taken from the issuer's SKID when available, otherwise it is derived from the issuer's public key. The issuer must have its public key configured first; calling AddSubjectKeyID on the issuer before this is recommended.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddAuthorityKeyID(issuer *Certificate) error {
	if issuer == nil {
		return fmt.Errorf("x509: nil issuer certificate")
	}
	return c.cert.AddAuthorityKeyID(issuer.cert)
}

// Fingerprint 计算证书指纹（十六进制小写）。
// alg 支持 "sha1"、"sha256"、"sm3"、"md5"、"sha384"、"sha512"。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Fingerprint computes the certificate's fingerprint as a lowercase hexadecimal string. The alg parameter accepts "sha1", "sha256", "sm3", "md5", "sha384", and "sha512".
//
// On failure, it returns an error wrapping an OpError describing the operation.
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
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// MarshalDER encodes the certificate in DER format.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) MarshalDER() ([]byte, error) {
	return c.cert.MarshalDER()
}

// NewCertificate 创建一个空证书（构建用）。
// 通过 Set* 方法配置字段后调用 Sign 完成签名；CreateCertificate 是一次性便捷版。
//
// NewCertificate creates an empty certificate for incremental construction. Configure it with the Set* methods and call Sign to finalize; CreateCertificate is a one-shot equivalent.
func NewCertificate() *Certificate {
	cert, err := core.NewCertificate()
	if err != nil {
		panic(err)
	}
	return &Certificate{cert: cert}
}

// SetVersion 设置证书版本（0=v1，2=v3）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetVersion sets the certificate version (0 = v1, 2 = v3).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetVersion(v int) error { return c.cert.SetVersion(v) }

// SetSerial 设置证书序列号。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetSerial sets the certificate serial number.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetSerial(serial int64) error { return c.cert.SetSerial(serial) }

// SetIssuer 设置签发者名字。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetIssuer sets the issuer name.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetIssuer(n *Name) error { return c.cert.SetIssuer(n.name) }

// SetSubject 设置主题名字。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetSubject sets the subject name.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetSubject(n *Name) error { return c.cert.SetSubject(n.name) }

// SetValidity 设置有效期。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetValidity sets the certificate validity window.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetValidity(notBefore, notAfter time.Time) error {
	return c.cert.SetValidity(notBefore, notAfter)
}

// SetPublicKey 设置证书公钥（支持 SM2 / RSA / ECDSA）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SetPublicKey sets the certificate public key (SM2 / RSA / ECDSA are supported).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SetPublicKey(pub PublicKey) error {
	if pub == nil {
		return fmt.Errorf("x509: nil public key")
	}
	return c.cert.SetPublicKey(pub.Key())
}

// AddBasicConstraints 添加 BasicConstraints 扩展（必须在 Sign 之前调用）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddBasicConstraints appends a BasicConstraints extension and must be called before Sign.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) AddBasicConstraints(isCA bool) error {
	return c.cert.AddBasicConstraints(isCA)
}

// Sign 使用签名私钥对证书签名（须先配置好版本/序列号/主题/签发者/有效期/公钥/扩展）。
// signer 支持 SM2 / RSA / ECDSA，摘要按密钥类型自动选择。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Sign signs the certificate with signer after version, serial, subject, issuer, validity, public key, and extensions have been configured. signer supports SM2 / RSA / ECDSA, and the digest is chosen automatically based on the key type.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) Sign(signer PrivateKey) error {
	if signer == nil {
		return fmt.Errorf("x509: nil signer")
	}
	return c.cert.Sign(signer.Key(), nil)
}

// PublicKey 返回证书公钥（SM2 包装；RSA/ECDSA 证书请用 PublicKeyPKey）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// PublicKey returns the certificate public key wrapped as *sm2.PublicKey. For RSA or ECDSA certificates use PublicKeyPKey.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) PublicKey() (*sm2.PublicKey, error) {
	k, err := c.cert.PublicKey()
	if err != nil {
		return nil, err
	}
	return sm2.PublicKeyFromPKey(k), nil
}

// PublicKeyPKey 返回证书公钥的底层核心密钥（适用任意算法，调用方负责 Close）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// PublicKeyPKey returns the certificate public key as the underlying *core.PKey, which works for any algorithm. The caller is responsible for closing it.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) PublicKeyPKey() (*core.PKey, error) {
	return c.cert.PublicKey()
}

// Verify 使用签发者公钥验证证书签名。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// Verify checks the certificate signature against signerPub.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) Verify(signerPub PublicKey) error {
	if signerPub == nil {
		return fmt.Errorf("x509: nil public key")
	}
	return c.cert.Verify(signerPub.Key())
}

// SelfSigned 报告证书是否为自签（主题与签发者名字完全一致，且签名可被自身公钥验证通过）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// SelfSigned reports whether the certificate is self-signed (subject and issuer names match exactly, and the signature verifies against the certificate's own public key).
//
// On failure, it returns an error wrapping an OpError describing the operation.
func (c *Certificate) SelfSigned() (bool, error) {
	if c == nil {
		return false, fmt.Errorf("x509: nil certificate")
	}
	if c.SubjectText() != c.IssuerText() {
		return false, nil
	}
	pub, err := c.PublicKey()
	if err != nil {
		return false, err
	}
	if err := c.Verify(pub); err != nil {
		// 签名不通过：仍视为"主题/签发者同名"但非真正自签，返回 false 且无错误。
		return false, nil
	}
	return true, nil
}

// Signature 返回证书的原始签名字节（DER 编码）；证书无效或未签名返回 nil。
//
// Signature returns the certificate's raw signature bytes (DER-encoded), or nil when the certificate is invalid or has no signature.
func (c *Certificate) Signature() []byte { return c.cert.Signature() }

// SignatureAlgorithm 返回证书签名算法的短名（如 "SM2-SM3"、"RSA-SHA256"、"ecdsa-with-SHA256"）；不可识别返回 ""。
//
// SignatureAlgorithm returns the signature algorithm short name (for example "SM2-SM3", "RSA-SHA256", or "ecdsa-with-SHA256"), or "" when the algorithm is not recognized.
func (c *Certificate) SignatureAlgorithm() string { return c.cert.SignatureAlgorithm() }

// SignatureAlgorithmOID 返回证书签名算法的 OID 点分文本（如 "1.2.156.10197.1.501"、"1.2.840.113549.1.1.11"）；不可读取返回 ""。
//
// SignatureAlgorithmOID returns the signature algorithm OID as a dotted string (for example "1.2.156.10197.1.501" for SM2-with-SM3 or "1.2.840.113549.1.1.11" for sha256WithRSAEncryption), or "" when the OID cannot be read.
func (c *Certificate) SignatureAlgorithmOID() string { return c.cert.SignatureAlgorithmOID() }

// PublicKey 表示可作为证书公钥的非对称密钥（SM2 / RSA / ECDSA）。
//
// PublicKey is the interface satisfied by asymmetric keys usable as a certificate public key (SM2 / RSA / ECDSA).
type PublicKey interface {
	Key() *core.PKey
}

// PrivateKey 表示可作为证书签名密钥的非对称密钥（SM2 / RSA / ECDSA）。
//
// PrivateKey is the interface satisfied by asymmetric keys usable as a certificate signing key (SM2 / RSA / ECDSA).
type PrivateKey interface {
	Key() *core.PKey
}

// CreateCertificate 创建一张由 signer 签发的证书。
// subject 为主题；issuer 为签发者（自签时与 subject 相同）；serial 为序列号；
// notBefore/notAfter 为有效期；pub 为证书公钥；signer 为签发私钥
// （自签时与 pub 对应，CA 签发时为 CA 私钥）。pub/signer 支持 SM2 / RSA / ECDSA。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// CreateCertificate builds and signs a certificate with signer. subject is the subject name; issuer is the issuer name (use the same value as subject for a self-signed certificate); serial is the certificate serial number; notBefore and notAfter define the validity window; pub is the certificate public key; signer is the issuer private key (paired with pub for self-signed certificates, or the CA key when issued by a CA). pub and signer support SM2 / RSA / ECDSA.
//
// On failure, it returns an error wrapping an OpError describing the operation.
func CreateCertificate(subject, issuer *Name, serial int64, notBefore, notAfter time.Time,
	pub PublicKey, signer PrivateKey) (*Certificate, error) {
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
	if err := cert.Sign(signer.Key(), nil); err != nil { // nil → 按密钥类型自动选摘要
		return nil, err
	}
	return &Certificate{cert: cert}, nil
}