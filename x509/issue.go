package x509

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// IssueOptions 控制 CA 依据 CSR 签发证书时的策略。
//
// 零值不可直接使用：Serial、NotBefore、NotAfter 必须显式给出，
// 否则 IssueCertificateFromRequest 返回错误。
//
// IssueOptions controls how a CA issues a certificate from a CSR.
//
// The zero value is not usable: Serial, NotBefore and NotAfter must be set
// explicitly, otherwise IssueCertificateFromRequest returns an error.
type IssueOptions struct {
	// Serial 是新证书的序列号；必填。
	//
	// Serial is the serial number of the issued certificate; required.
	Serial int64

	// NotBefore / NotAfter 是新证书的有效期窗口；必填且 NotAfter 必须晚于 NotBefore。
	//
	// NotBefore and NotAfter bound the validity window of the issued
	// certificate; both are required and NotAfter must be later than NotBefore.
	NotBefore time.Time
	NotAfter  time.Time

	// Extensions 是 CA 显式指定的扩展（按 NID + OpenSSL 配置串）。
	//
	// 与 CopyRequestExtensions 拷贝过来的同名扩展冲突时，以本字段为准
	// （见 IssueCertificateFromRequest 的合并顺序）。
	//
	// Extensions are the extensions the CA explicitly requests, as NID plus
	// OpenSSL configuration string.
	//
	// When one of them collides with an extension copied through
	// CopyRequestExtensions, this field wins (see the merge order documented
	// on IssueCertificateFromRequest).
	Extensions []Extension

	// CopyRequestExtensions 控制是否把 CSR 的扩展拷贝到新证书。
	//
	// 默认为 false：与 `openssl ca` 的 copy_extensions none 一致。盲目拷贝会让
	// 请求方获颁任意域名 / 任意用途的证书，因此开启时也只拷贝白名单扩展
	// （SAN / KeyUsage / EKU / BasicConstraints），其余扩展一律忽略。
	//
	// CopyRequestExtensions controls whether the CSR's extensions are carried
	// over to the issued certificate.
	//
	// It defaults to false, matching `openssl ca`'s copy_extensions none.
	// Blindly copying them would let a requester obtain a certificate for any
	// name or purpose, so even when enabled only a whitelist is copied
	// (SAN / KeyUsage / EKU / BasicConstraints) and the rest are ignored.
	CopyRequestExtensions bool
}

// csrExtCopyAllowed 列出开启 CopyRequestExtensions 时允许从 CSR 拷贝的扩展短名。
//
// 白名单刻意保守：只放行「CA 复核后仍然安全」的四类扩展，其余（含
// nameConstraints / certificatePolicies / nsComment 等）一律不拷。
//
// csrExtCopyAllowed lists the extension short names that may be copied from a
// CSR when CopyRequestExtensions is enabled.
//
// The whitelist is deliberately conservative: only the four extension types
// that stay safe after CA review are allowed; everything else (including
// nameConstraints, certificatePolicies and nsComment) is dropped.
var csrExtCopyAllowed = map[string]bool{
	"subjectAltName":   true,
	"keyUsage":         true,
	"extendedKeyUsage": true,
	"basicConstraints": true,
}

// IssueCertificateFromRequest 依据 CSR 用 CA 私钥签发一张证书。
//
// req 为请求方 CSR；issuer 为签发者 CA 证书（其 subject 成为新证书的 issuer，
// 同时提供 authorityKeyIdentifier 的 keyid）；signer 为 CA 私钥。
//
// 新证书固定为 v3，并自动补 subjectKeyIdentifier 与 authorityKeyIdentifier。
//
// 扩展合并顺序（后者覆盖前者）：
//  1. opts.Extensions（CA 显式指定）；
//  2. 开启 opts.CopyRequestExtensions 时，按 CSR 中的出现顺序拷贝白名单扩展
//     （SAN / KeyUsage / EKU / BasicConstraints），并跳过与第 1 步 NID 相同者。
//
// 即：**CA 的显式意图始终优先于请求方的请求**。
//
// 未开启 CopyRequestExtensions 时，CSR 的扩展一律不进入新证书——这与
// `openssl ca` 的 copy_extensions none 一致，也是防「请求方自选 SAN」的安全底线。
//
// 返回的证书拥有自己的句柄，调用方须调用 Close。
//
// 失败时返回包装了 OpError 的错误，或带上下文的参数错误。
//
// IssueCertificateFromRequest issues a certificate from a CSR using the CA's
// private key.
//
// req is the requester's CSR; issuer is the issuing CA certificate (its subject
// becomes the issuer name of the new certificate and also supplies the
// authorityKeyIdentifier keyid); signer is the CA private key.
//
// The issued certificate is always v3 and receives its subjectKeyIdentifier and
// authorityKeyIdentifier automatically.
//
// Extensions are merged in this order, later entries overriding earlier ones:
//  1. opts.Extensions, the CA's explicit selection;
//  2. when opts.CopyRequestExtensions is set, the whitelisted extensions of the
//     CSR (SAN / KeyUsage / EKU / BasicConstraints) in their original order,
//     skipping any NID already produced in step 1.
//
// In other words **the CA's explicit intent always wins over the requester's
// request**.
//
// Without CopyRequestExtensions the CSR's extensions never reach the issued
// certificate, matching `openssl ca`'s copy_extensions none and preserving the
// security floor against a requester picking its own SAN.
//
// The returned certificate owns its handle; the caller must Close it.
//
// On failure, it returns an error wrapping an OpError or a contextual argument
// error.
func IssueCertificateFromRequest(req *CertificateRequest, issuer *Certificate,
	signer asym.PrivateKey, opts *IssueOptions) (ret *Certificate, retErr error) {
	if req == nil || req.req == nil {
		return nil, fmt.Errorf("x509: nil certificate request")
	}
	if issuer == nil || issuer.cert == nil {
		return nil, fmt.Errorf("x509: nil issuer certificate")
	}
	if opts == nil {
		return nil, fmt.Errorf("x509: nil issue options")
	}
	if !opts.NotAfter.After(opts.NotBefore) {
		return nil, fmt.Errorf("x509: notAfter must be after notBefore")
	}
	if err := req.Verify(); err != nil {
		return nil, fmt.Errorf("x509: request signature invalid: %w", err)
	}

	pub, err := req.PublicKey()
	if err != nil {
		return nil, err
	}
	defer func() { _ = asym.Close(pub) }()

	subject := req.SubjectName()
	if subject == nil {
		return nil, fmt.Errorf("x509: request has no subject name")
	}

	cert := NewCertificate()
	defer func() {
		if retErr != nil {
			_ = cert.Close()
		}
	}()
	if err := cert.SetVersion(2); err != nil { // v3
		return nil, err
	}
	if err := cert.SetSerial(opts.Serial); err != nil {
		return nil, err
	}
	if err := cert.SetIssuer(issuer.SubjectName()); err != nil {
		return nil, err
	}
	if err := cert.SetSubject(subject); err != nil {
		return nil, err
	}
	if err := cert.SetValidity(opts.NotBefore, opts.NotAfter); err != nil {
		return nil, err
	}
	if err := cert.SetPublicKey(pub); err != nil {
		return nil, err
	}

	// 1. CA 显式指定的扩展
	if err := cert.AddExtensions(opts.Extensions...); err != nil {
		return nil, fmt.Errorf("x509: add CA extensions: %w", err)
	}

	// 2. 可选的 CSR 白名单扩展，跳过与第 1 步冲突者
	if opts.CopyRequestExtensions {
		taken := make(map[int]bool, len(opts.Extensions))
		for _, e := range opts.Extensions {
			taken[e.Nid] = true
		}
		if _, err := req.req.CopyExtensionTo(cert.cert,
			func(nid int, field string, _ bool) bool {
				return csrExtCopyAllowed[field] && !taken[nid]
			}); err != nil {
			return nil, fmt.Errorf("x509: copy request extensions: %w", err)
		}
	}

	if err := cert.AddSubjectKeyID(); err != nil {
		return nil, err
	}
	if err := cert.AddAuthorityKeyID(issuer); err != nil {
		return nil, err
	}
	if err := cert.Sign(signer); err != nil {
		return nil, err
	}
	return cert, nil
}
