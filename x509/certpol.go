package x509

import (
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// certificatePoliciesOID 是 certificatePolicies 扩展的 OID（RFC 5280 §4.2.1.4）。
//
// certificatePoliciesOID is the OID of the certificatePolicies extension
// (RFC 5280 §4.2.1.4).
const certificatePoliciesOID = "2.5.29.32"

// CertificatePolicy 表示 certificatePolicies 扩展中的一条证书策略。
//
// OID 是策略标识符（点分形式，如 "1.2.3.4"），必填且不可重复。
// CPSURIs 是 id-qt-cps 限定符的证书策略声明 URL 列表（RFC 5280 §4.2.1.4）——
// policyQualifiers 可含多条同类型限定符，顺序即写入顺序；为空表示不带该
// 限定符。URL 只允许 IA5（7-bit ASCII）字符。
// UserNotice 是 id-qt-unotice 限定符，为 nil 表示不带该限定符。
//
// 一条策略最多带一个 userNotice 限定符；CPS 与 userNotice 同时给出时，CPS 在前。
//
// CertificatePolicy is one certificate policy inside a certificatePolicies
// extension.
//
// OID is the policy identifier in dotted form (for example "1.2.3.4"); it is
// mandatory and must not repeat across the policies of one extension.
// CPSURIs is the list of Certification Practice Statement URLs carried by the
// id-qt-cps qualifier (RFC 5280 §4.2.1.4) — policyQualifiers may hold
// several qualifiers of the same type, and their order is preserved; an
// empty list means the qualifier is absent, and the URLs may only contain
// IA5 (7-bit ASCII) characters.
// UserNotice is the id-qt-unotice qualifier; a nil value means the qualifier
// is absent.
//
// A policy carries at most one userNotice qualifier; when a CPS and a
// userNotice are both present, the CPS comes first.
type CertificatePolicy struct {
	// OID 为策略标识符（点分形式），必填。
	OID string
	// CPSURIs 为 id-qt-cps 限定符的策略声明 URL 列表，可为空。
	CPSURIs []string
	// UserNotice 为 id-qt-unotice 限定符，可为 nil。
	UserNotice *UserNotice
}

// UserNotice 表示 certificatePolicies 的 userNotice 限定符
// （RFC 5280 §4.2.1.4 的 UserNotice / NoticeReference）。
//
// Organization 是通知机构名；给出时同时产生 NoticeReference，其中包含
// NoticeNumbers（通知编号列表，可为空）。NoticeNumbers 非空而 Organization
// 为空属于非法配置（NoticeReference 的 organization 是必填项），会返回错误。
// ExplicitText 是直接展示给证书使用者的通知文本。
// 三个字段全为空同样属于非法配置，会返回错误。
//
// 文本以 UTF8String 编码。铜锁 openssl 的配置文件路径用 VisibleString，
// 对非 ASCII 内容会产出不合规的 DER；本库统一用 UTF8String，铜锁可以正常
// 读回。
//
// UserNotice is the userNotice qualifier of a certificatePolicies extension
// (the UserNotice / NoticeReference structures of RFC 5280 §4.2.1.4).
//
// Organization is the name of the notice organization; when it is given, a
// NoticeReference is produced, containing NoticeNumbers (the list of notice
// numbers, which may be empty). Notice numbers without an organization are
// invalid configuration (organization is mandatory inside NoticeReference) and
// are rejected with an error. ExplicitText is the notice shown directly to
// certificate users. An entirely empty notice is likewise rejected.
//
// The text is encoded as UTF8String. The Tongsuo openssl configuration path
// uses VisibleString, which produces non-conformant DER for non-ASCII
// content; this library always uses UTF8String, which Tongsuo reads back
// correctly.
type UserNotice struct {
	// Organization 为通知机构名，可为空。
	Organization string
	// NoticeNumbers 为通知编号列表，可为空。
	NoticeNumbers []int
	// ExplicitText 为通知文本，可为空。
	ExplicitText string
}

// AddCertificatePolicies 向证书追加 certificatePolicies 扩展。
//
// policies 为策略列表，不可为空；列表中不可出现重复的 OID。每条策略可带
// 多条 CPS（id-qt-cps）与至多一条 userNotice（id-qt-unotice）限定符。critical 为真时
// 扩展标记为 critical（RFC 5280 允许该扩展为 critical，但证书策略扩展通常
// 标记为非 critical）。
//
// 须在 Sign 之前调用；Sign 之后证书即不可变，再次调用返回错误。证书中已
// 存在 certificatePolicies 扩展时返回
// "x509: extension already present (nid 89)"——需覆盖请先调用
// RemoveExtension("certificatePolicies")。
//
// 与 AddExtension 的配置语法不同，本方法不经过 OpenSSL 的扩展配置解析，
// 因此可以表达配置文件才能表达的限定符结构（OpenSSL 的 certificatePolicies
// 只认配置文件里的 "@section" 形式）。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddCertificatePolicies appends a certificatePolicies extension to the
// certificate.
//
// policies must not be empty and must not repeat an OID. Each policy may carry
// several CPS (id-qt-cps) qualifiers and at most one userNotice (id-qt-unotice)
// qualifier. The extension
// is marked critical when critical is true (RFC 5280 permits the extension to
// be critical, although certificate policy extensions are usually not).
//
// It must be called before Sign. Once the certificate is signed it becomes
// immutable and further calls return an error. When the certificate already
// carries a certificatePolicies extension the call returns
// "x509: extension already present (nid 89)"; to overwrite it, call
// RemoveExtension("certificatePolicies") first.
//
// Unlike the configuration syntax of AddExtension, this method does not go
// through OpenSSL's extension configuration parser, so it can express the
// qualifier structures that are only reachable through a configuration file
// (OpenSSL's certificatePolicies only accepts the "@section" form of a
// configuration file).
//
// On failure, it returns an error wrapping an OpError describing the
// operation.
func (c *Certificate) AddCertificatePolicies(policies []CertificatePolicy, critical bool) error {
	der, err := encodeCertificatePolicies(policies)
	if err != nil {
		return err
	}
	nid, err := core.ExtNidByName(certificatePoliciesOID)
	if err != nil {
		return err
	}
	return c.cert.AddExtensionDER(nid, critical, der)
}

// CertificatePolicies 返回证书中的 certificatePolicies 策略列表。
//
// 证书没有该扩展时返回 (nil, nil)；扩展内容不是合法的 certificatePolicies
// DER 时返回错误。
//
// CertificatePolicies returns the certificatePolicies entries of the
// certificate.
//
// It returns (nil, nil) when the certificate has no such extension, and an
// error when the extension content is not a valid certificatePolicies DER
// encoding.
func (c *Certificate) CertificatePolicies() ([]CertificatePolicy, error) {
	return certificatePoliciesFromExtensions(c.Extensions())
}

// AddCertificatePolicies 向 CSR 追加 certificatePolicies 扩展。
//
// policies 为策略列表，不可为空；列表中不可出现重复的 OID。每条策略可带
// 多条 CPS（id-qt-cps）与至多一条 userNotice（id-qt-unotice）限定符。critical 为真时
// 扩展标记为 critical。
//
// 须在 Sign 之前调用；Sign 之后 CSR 即不可变，再次调用返回错误。扩展在
// Sign / MarshalDER 之前以**单次**原生调用提交，因此与铜锁 8.4 / 8.5 的
// X509_REQ_add_extensions 合并语义差异无关。
//
// 与 AddExtension 的配置语法不同，本方法不经过 OpenSSL 的扩展配置解析，
// 因此可以表达配置文件才能表达的限定符结构。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddCertificatePolicies appends a certificatePolicies extension to the CSR.
//
// policies must not be empty and must not repeat an OID. Each policy may carry
// several CPS (id-qt-cps) qualifiers and at most one userNotice (id-qt-unotice)
// qualifier. The extension
// is marked critical when critical is true.
//
// It must be called before Sign. Once the CSR is signed it becomes immutable
// and further calls return an error. The extension is committed with a
// **single** native call before Sign / MarshalDER, so the result does not
// depend on the differing X509_REQ_add_extensions merge semantics of Tongsuo
// 8.4 and 8.5.
//
// Unlike the configuration syntax of AddExtension, this method does not go
// through OpenSSL's extension configuration parser, so it can express the
// qualifier structures that are only reachable through a configuration file.
//
// On failure, it returns an error wrapping an OpError describing the
// operation.
func (r *CertificateRequest) AddCertificatePolicies(policies []CertificatePolicy, critical bool) error {
	der, err := encodeCertificatePolicies(policies)
	if err != nil {
		return err
	}
	nid, err := core.ExtNidByName(certificatePoliciesOID)
	if err != nil {
		return err
	}
	return r.req.AddExtensionDER(nid, critical, der)
}

// CertificatePolicies 返回 CSR 中的 certificatePolicies 策略列表。
//
// CSR 没有该扩展时返回 (nil, nil)；扩展内容不是合法的 certificatePolicies
// DER 时返回错误。
//
// CertificatePolicies returns the certificatePolicies entries of the CSR.
//
// It returns (nil, nil) when the CSR has no such extension, and an error
// when the extension content is not a valid certificatePolicies DER encoding.
func (r *CertificateRequest) CertificatePolicies() ([]CertificatePolicy, error) {
	return certificatePoliciesFromExtensions(r.Extensions())
}

// AddCertificatePolicies 向 CRL 追加 certificatePolicies 扩展。
//
// policies 为策略列表，不可为空；列表中不可出现重复的 OID。每条策略可带
// 多条 CPS（id-qt-cps）与至多一条 userNotice（id-qt-unotice）限定符。critical 为真时
// 扩展标记为 critical。
//
// 须在 Sign 之前调用；CRL 中已存在 certificatePolicies 扩展时返回
// "x509: extension already present (nid 89)"。
//
// ⚠️ certificatePolicies 并非 RFC 5280 §5.2 定义的 CRL 扩展。本方法用于
// 与 `openssl ca -crlexts` 的配置产物对齐，校验方通常会忽略该扩展。
//
// 失败时返回包装了 OpError 的错误，OpError 描述了失败的底层操作。
//
// AddCertificatePolicies appends a certificatePolicies extension to the CRL.
//
// policies must not be empty and must not repeat an OID. Each policy may carry
// several CPS (id-qt-cps) qualifiers and at most one userNotice (id-qt-unotice)
// qualifier. The extension
// is marked critical when critical is true.
//
// It must be called before Sign. When the CRL already carries a
// certificatePolicies extension the call returns
// "x509: extension already present (nid 89)".
//
// ⚠️ certificatePolicies is not a CRL extension defined by RFC 5280 §5.2. This
// method exists to align with the output of `openssl ca -crlexts`; verifiers
// normally ignore the extension.
//
// On failure, it returns an error wrapping an OpError describing the
// operation.
func (b *CRLBuilder) AddCertificatePolicies(policies []CertificatePolicy, critical bool) error {
	if b == nil || b.crl == nil {
		return errBuilderClosed()
	}
	der, err := encodeCertificatePolicies(policies)
	if err != nil {
		return err
	}
	nid, err := core.ExtNidByName(certificatePoliciesOID)
	if err != nil {
		return err
	}
	return b.crl.AddExtensionDER(nid, critical, der)
}

// CertificatePolicies 返回 CRL 中的 certificatePolicies 策略列表。
//
// CRL 没有该扩展时返回 (nil, nil)；扩展内容不是合法的 certificatePolicies
// DER 时返回错误。
//
// CertificatePolicies returns the certificatePolicies entries of the CRL.
//
// It returns (nil, nil) when the CRL has no such extension, and an error
// when the extension content is not a valid certificatePolicies DER encoding.
func (c *CRL) CertificatePolicies() ([]CertificatePolicy, error) {
	return certificatePoliciesFromExtensions(c.Extensions())
}

// certificatePoliciesFromExtensions 从扩展列表中取出 certificatePolicies 扩展
// 并解析其策略列表；没有该扩展时返回 (nil, nil)。
//
// certificatePoliciesFromExtensions picks the certificatePolicies extension out
// of exts and parses its policy list, returning (nil, nil) when the extension
// is absent.
func certificatePoliciesFromExtensions(exts []Extension) ([]CertificatePolicy, error) {
	for _, e := range exts {
		if e.OID != certificatePoliciesOID {
			continue
		}
		return parseCertificatePolicies(e.Data)
	}
	return nil, nil
}
