package x509

import (
	"bytes"
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
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
// ⚠️ 信任前提：本函数**不校验 CRL 的签名/有效期**——它只做 issuer 名 +
// serial 的匹配。调用方必须先通过 CRL.Verify（或证书链验证流程）确认每张
// CRL 由可信签发者签名且未过期，再把该 CRL 传入；对不可信/被篡改的 CRL，
// 任何能伪造同名签发者的输入都可能让任意序列号被误报为已吊销。
//
// RevocationCheck reports whether cert is revoked by any of the supplied CRLs. A CRL is only considered when its issuer matches the certificate's issuer and the serial number matches; an unrevoked certificate yields nil, while a revoked one produces a descriptive error.
//
// ⚠️ Trust precondition: this function does NOT verify the CRL's signature
// or validity window — it only matches issuer name + serial. Callers MUST
// first confirm each CRL is signed by a trusted issuer and still in
// force (via CRL.Verify or a chain-validation flow) before passing it
// in; an untrusted / tampered CRL with a forged same-name issuer could
// otherwise make any serial number appear revoked.
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

// Verify 校验 CRL 的签名（以签发者证书 issuer 的公钥），用于在把 CRL 交给
// RevocationCheck 之前确认其真实性。
//
// issuer 支持 SM2 / RSA / ECDSA 证书；验签使用 CRL 内声明的签名算法与摘要。
// 验签失败返回错误（含底层 OpError）；nil 接收者/签发者返回相应错误。
//
// Verify checks the CRL signature against the public key of the issuer
// certificate, letting callers establish trust before handing the CRL
// to RevocationCheck.
//
// issuer supports SM2 / RSA / ECDSA certificates; verification uses the
// signature algorithm and digest recorded in the CRL. A failed check
// returns an error (including the wrapped OpError); nil receivers /
// issuers return explicit errors.
func (c *CRL) Verify(issuer *Certificate) error {
	if c == nil || c.crl == nil {
		return fmt.Errorf("x509: nil CRL")
	}
	if issuer == nil {
		return fmt.Errorf("x509: nil issuer certificate")
	}
	pub, err := issuer.cert.PublicKey()
	if err != nil {
		return err
	}
	defer func() { _ = pub.Close() }()
	return c.crl.Verify(pub)
}

// RevocationReason 为 CRL 吊销原因码（RFC 5280 §5.3.1 CRLReason）。
//
// 取值与 `openssl crl -crl_reason` 接受的名字、以及 `openssl crl -text` 打印的
// 长名一一对应；`ReasonUnspecified`(0) 表示只写码、不表达特定原因。
//
// RevocationReason is a CRL revocation reason code (RFC 5280 §5.3.1
// CRLReason).
//
// The values match the names accepted by `openssl crl -crl_reason` and the
// long names printed by `openssl crl -text`; ReasonUnspecified (0) carries no
// specific cause.
type RevocationReason int

// CRL 吊销原因码常量（RFC 5280 §5.3.1；7 保留未定义）。
//
// The CRL revocation reason constants (RFC 5280 §5.3.1; 7 is reserved and
// undefined).
const (
	// ReasonUnspecified 表示未指明具体原因（码值 0）。
	//
	// ReasonUnspecified means no specific cause is given (code 0).
	ReasonUnspecified RevocationReason = 0
	// ReasonKeyCompromise 表示密钥泄露（码值 1）。
	//
	// ReasonKeyCompromise means the key was compromised (code 1).
	ReasonKeyCompromise RevocationReason = 1
	// ReasonCACompromise 表示 CA 密钥泄露（码值 2）。
	//
	// ReasonCACompromise means the CA key was compromised (code 2).
	ReasonCACompromise RevocationReason = 2
	// ReasonAffiliationChanged 表示归属变更（码值 3）。
	//
	// ReasonAffiliationChanged means the subject's affiliation changed (code 3).
	ReasonAffiliationChanged RevocationReason = 3
	// ReasonSuperseded 表示已被取代（码值 4）。
	//
	// ReasonSuperseded means the certificate was superseded (code 4).
	ReasonSuperseded RevocationReason = 4
	// ReasonCessationOfOperation 表示停止运营（码值 5）。
	//
	// ReasonCessationOfOperation means the certificate is no longer needed (code 5).
	ReasonCessationOfOperation RevocationReason = 5
	// ReasonCertificateHold 表示临时挂起（码值 6）。
	//
	// ReasonCertificateHold means the certificate is on hold (code 6).
	ReasonCertificateHold RevocationReason = 6
	// ReasonRemoveFromCRL 表示从 CRL 中移除（码值 8）。
	//
	// ReasonRemoveFromCRL means the certificate is removed from the CRL (code 8).
	ReasonRemoveFromCRL RevocationReason = 8
	// ReasonPrivilegeWithdrawn 表示权限被撤销（码值 9）。
	//
	// ReasonPrivilegeWithdrawn means a privilege was withdrawn (code 9).
	ReasonPrivilegeWithdrawn RevocationReason = 9
	// ReasonAACompromise 表示属性权威密钥泄露（码值 10）。
	//
	// ReasonAACompromise means an attribute authority key was compromised (code 10).
	ReasonAACompromise RevocationReason = 10
)

// validRevocationReason 报告 r 是否为 RFC 5280 定义的吊销原因码（7 为保留值，不接受）。
func validRevocationReason(r RevocationReason) bool {
	switch r {
	case ReasonUnspecified, ReasonKeyCompromise, ReasonCACompromise,
		ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation,
		ReasonCertificateHold, ReasonRemoveFromCRL, ReasonPrivilegeWithdrawn,
		ReasonAACompromise:
		return true
	default:
		return false
	}
}

// CRLBuilder 分步构建并签发 CRL（对应 `openssl crl` / `openssl ca -gencrl` 的签发流程）。
//
// 典型用法：
//
//	b, err := x509.NewCRLBuilder(caCert) // 自动取 CA subject 作 issuer 并补 AKID
//	if err != nil { … }
//	defer b.Close()                      // 未签名时由本调用释放
//	b.SetNumber(42)
//	b.SetThisUpdate(now)
//	b.SetNextUpdate(now.Add(24 * time.Hour))
//	b.Revoke(leafCert, now, x509.ReasonKeyCompromise)
//	crl, err := b.Sign(caKey)            // 句柄转移给返回值，builder 随之失效
//	if err != nil { … }
//	defer crl.Close()
//
// 生命周期：builder 自 NewCRLBuilder 起持有一个底层 X509_CRL 句柄；Sign 成功后该
// 句柄**转移**给返回的 *CRL，builder 变空（再调用任何方法返回
// "x509: CRL builder already signed or closed"）。未调用 Sign 时必须显式 Close，
// 不要只依赖 finalizer（AGENTS.md §4.4）。
//
// CRLBuilder builds and signs a CRL step by step (mirroring the `openssl crl`
// / `openssl ca -gencrl` flow).
//
// Typical use:
//
//	b, err := x509.NewCRLBuilder(caCert) // takes the CA subject as issuer and adds AKID
//	if err != nil { … }
//	defer b.Close()                      // releases the handle when not signed
//	b.SetNumber(42)
//	b.SetThisUpdate(now)
//	b.SetNextUpdate(now.Add(24 * time.Hour))
//	b.Revoke(leafCert, now, x509.ReasonKeyCompromise)
//	crl, err := b.Sign(caKey)            // ownership moves to the result; the builder expires
//	if err != nil { … }
//	defer crl.Close()
//
// Lifetime: the builder owns an underlying X509_CRL handle from
// NewCRLBuilder onwards. After a successful Sign that handle is
// **transferred** to the returned *CRL and the builder is emptied (any later
// method call returns "x509: CRL builder already signed or closed"). When
// Sign is never called, Close must be invoked explicitly rather than relying
// on the finalizer (AGENTS.md §4.4).
type CRLBuilder struct {
	crl       *core.CRL
	hasNumber bool
	hasThis   bool
}

// NewCRLBuilder 创建 CRL 构建器：以 issuer 证书的 subject 作为 CRL 签发者名字，
// 并自动追加 authorityKeyIdentifier 扩展（keyid 取自该证书）。
//
// ⚠️ issuer 必须是签发被吊销证书的那张 CA 证书本体（CRL 的 issuer 字段按 RFC 5280
// §5.1.2.3 等于 CA 的 subject，而非 CA 自身的 issuer）。
//
// issuer 为 nil 时返回 "x509: nil issuer certificate"；错误以 OpError 包装。
//
// NewCRLBuilder creates a CRL builder: the issuer certificate's subject
// becomes the CRL issuer name and the authorityKeyIdentifier extension is
// added automatically (keyid taken from that certificate).
//
// ⚠️ issuer must be the CA certificate that issued the certificates being
// revoked (per RFC 5280 §5.1.2.3 the CRL issuer field equals the CA's
// subject, not the CA's own issuer).
//
// A nil issuer returns "x509: nil issuer certificate". Errors are wrapped as
// OpError.
func NewCRLBuilder(issuer *Certificate) (*CRLBuilder, error) {
	if issuer == nil || issuer.cert == nil {
		return nil, fmt.Errorf("x509: nil issuer certificate")
	}
	crl, err := core.NewCRLForIssuer(issuer.cert.SubjectName())
	if err != nil {
		return nil, err
	}
	if err := crl.AddAuthorityKeyID(issuer.cert); err != nil {
		_ = crl.Close()
		return nil, err
	}
	return &CRLBuilder{crl: crl}, nil
}

// errBuilderClosed 为构建器已签发或已释放时返回的错误。
//
// errBuilderClosed is returned when the builder has already been signed or
// closed.
func errBuilderClosed() error {
	return fmt.Errorf("x509: CRL builder already signed or closed")
}

// SetNumber 设置 CRL Number 扩展值（RFC 5280 §5.2.3，单调递增）。
//
// 须在 Sign 之前调用；未显式设置时 Sign 会写入默认值 1（与 `openssl ca -gencrl`
// 一致）。
//
// SetNumber sets the CRL Number extension value (RFC 5280 §5.2.3, monotonically
// increasing).
//
// Must be invoked before Sign; when never set, Sign writes the default value 1
// (matching `openssl ca -gencrl`).
func (b *CRLBuilder) SetNumber(n int64) error {
	if b == nil || b.crl == nil {
		return errBuilderClosed()
	}
	if err := b.crl.SetNumber(n); err != nil {
		return err
	}
	b.hasNumber = true
	return nil
}

// SetThisUpdate 设置 CRL 的 thisUpdate 时间（必填）。
//
// 未设置就调用 Sign 会返回 "x509: CRL builder: thisUpdate not set"。
//
// SetThisUpdate sets the CRL's thisUpdate time (mandatory).
//
// Calling Sign without it returns "x509: CRL builder: thisUpdate not set".
func (b *CRLBuilder) SetThisUpdate(t time.Time) error {
	if b == nil || b.crl == nil {
		return errBuilderClosed()
	}
	if err := b.crl.SetThisUpdate(t); err != nil {
		return err
	}
	b.hasThis = true
	return nil
}

// SetNextUpdate 设置 CRL 的 nextUpdate 时间（可选；零值表示不写该字段）。
//
// SetNextUpdate sets the CRL's nextUpdate time (optional; the zero value
// leaves the field unset).
func (b *CRLBuilder) SetNextUpdate(t time.Time) error {
	if b == nil || b.crl == nil {
		return errBuilderClosed()
	}
	return b.crl.SetNextUpdate(t)
}

// Revoke 向 CRL 追加一条吊销记录。
//
// cert 为被吊销的证书（取其序列号）；at 为吊销生效时间；reason 为吊销原因码，
// 必须是本包定义的 RevocationReason 常量之一（否则返回错误）。
//
// ⚠️ 本函数不校验 cert 的签发者是否与本构建器的 issuer 一致——把非本 CA 签发的
// 证书放进 CRL 会产出一张语义错误（且可能误导验证方）的 CRL，责任在调用方。
//
// cert 为 nil 返回 "x509: nil certificate"；reason 非法返回描述性错误。
//
// Revoke appends one revocation record to the CRL.
//
// cert is the certificate being revoked (its serial number is used), at is
// when the revocation takes effect and reason is the revocation reason code,
// which must be one of the RevocationReason constants defined in this package
// (an error is returned otherwise).
//
// ⚠️ This function does not check that cert was issued by this builder's
// issuer — putting a foreign certificate into a CRL produces a semantically
// wrong CRL (which may mislead verifiers), and that responsibility lies with
// the caller.
//
// A nil cert returns "x509: nil certificate"; an invalid reason returns a
// descriptive error.
func (b *CRLBuilder) Revoke(cert *Certificate, at time.Time, reason RevocationReason) error {
	if b == nil || b.crl == nil {
		return errBuilderClosed()
	}
	if cert == nil || cert.cert == nil {
		return fmt.Errorf("x509: nil certificate")
	}
	if !validRevocationReason(reason) {
		return fmt.Errorf("x509: invalid revocation reason %d", int(reason))
	}
	return b.crl.AddRevokedEntry(cert.Serial(), at, int(reason))
}

// Sign 用签发者私钥签名并返回可导出的 CRL。
//
// signer 支持 SM2 / RSA / ECDSA / Ed25519 / Ed448；调用后构建器持有的底层句柄
// **转移**给返回值，builder 随之失效（再次调用任何方法返回
// "x509: CRL builder already signed or closed"）。
//
// 未设置 thisUpdate 返回 "x509: CRL builder: thisUpdate not set"；未设置 CRL
// Number 时自动写 1；signer 为 nil 或类型不受支持时返回相应错误。
//
// Sign signs the CRL with the issuer's private key and returns an exportable
// CRL.
//
// signer may be an SM2 / RSA / ECDSA / Ed25519 / Ed448 key. After the call
// the builder's underlying handle is **transferred** to the returned value
// and the builder expires (any later method call returns "x509: CRL builder
// already signed or closed").
//
// When thisUpdate was never set it returns "x509: CRL builder: thisUpdate not
// set"; when the CRL Number was never set the default 1 is written
// automatically; a nil or unsupported signer yields the corresponding error.
func (b *CRLBuilder) Sign(signer asym.PrivateKey) (*CRL, error) {
	if b == nil || b.crl == nil {
		return nil, errBuilderClosed()
	}
	if !b.hasThis {
		return nil, fmt.Errorf("x509: CRL builder: thisUpdate not set")
	}
	pk, err := corePrivateKey(signer)
	if err != nil {
		return nil, err
	}
	if !b.hasNumber {
		if err := b.crl.SetNumber(1); err != nil {
			return nil, err
		}
		b.hasNumber = true
	}
	if err := b.crl.Sign(pk); err != nil {
		return nil, err
	}
	out := &CRL{crl: b.crl}
	b.crl = nil
	return out, nil
}

// Close 释放尚未签发的 CRL 句柄。
//
// 调用是幂等的：对 nil 接收者、已签发（句柄已转移）或已释放的构建器调用返回 nil。
//
// Close releases the not-yet-signed CRL handle.
//
// The call is idempotent: invoking it on a nil receiver, on a builder that has
// already signed (its handle having been transferred) or on one that has
// already been closed returns nil.
func (b *CRLBuilder) Close() error {
	if b == nil || b.crl == nil {
		return nil
	}
	err := b.crl.Close()
	b.crl = nil
	return err
}
