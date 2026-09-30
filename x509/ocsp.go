// 本文件提供 OCSP（在线证书状态协议）：请求构造（CreateOCSPRequest）、响应解析
// （ParseOCSPResponse）与响应签名验证（Response.Verify，复用 X.509 链验证）。
//
// 原为独立的 ocsp 包，本次重构并入 x509（roadmap §3.10）：PKI 家族（证书 / CSR /
// CRL / OCSP / 链验证）收口于一个包，`Store.AddCRL(*CRL)` 不再跨包。同包可能重名的
// 符号已加前缀：Good/Revoked/Unknown → OCSPGood/OCSPRevoked/OCSPUnknown；
// CreateRequest/ParseResponse → CreateOCSPRequest/ParseOCSPResponse。
//
// This file provides OCSP (Online Certificate Status Protocol): request
// construction (CreateOCSPRequest), response parsing (ParseOCSPResponse) and
// response signature verification (Response.Verify, reusing the X.509 chain
// validation path).
//
// It used to be a standalone ocsp package and was merged into x509 by this
// refactor (roadmap §3.10) so the PKI family (certificates, CSR, CRL, OCSP and
// chain verification) lives in a single package. Symbols that could collide
// in-package carry a prefix: Good/Revoked/Unknown became
// OCSPGood/OCSPRevoked/OCSPUnknown and CreateRequest/ParseResponse became
// CreateOCSPRequest/ParseOCSPResponse.
package x509

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// OCSP 证书状态码（对应 OCSP CertStatus 枚举）。
//
// OCSP certificate status codes (mirroring the OCSP CertStatus enum).
const (
	// OCSPGood 表示证书状态为 good。
	//
	// OCSPGood reports a good certificate status.
	OCSPGood = 0
	// OCSPRevoked 表示证书已被吊销。
	//
	// OCSPRevoked reports a revoked certificate status.
	OCSPRevoked = 1
	// OCSPUnknown 表示响应方不认识该证书。
	//
	// OCSPUnknown reports an unknown certificate status.
	OCSPUnknown = 2
)

// CreateOCSPRequest 生成对 cert（由 issuer 签发）的 OCSP 状态请求（DER）。
// hash 取 "sha1" / "sha256" / "sm3"，空为 sha1。
// cert 与 issuer 均不得为 nil；hash 不在支持列表时返回错误。
//
// 原为 ocsp.CreateRequest，因与 internal/core.CreateOCSPRequest 同名语义而异名，
// 此处加 OCSP 前缀（roadmap §3.10）。
//
// CreateOCSPRequest builds an OCSP request (DER-encoded) asking for the
// status of cert, which was signed by issuer. Both cert and issuer must
// be non-nil. hash may be "sha1", "sha256", or "sm3"; an empty hash
// selects sha1.
//
// It was ocsp.CreateRequest and carries an OCSP prefix here for clarity
// (roadmap §3.10).
func CreateOCSPRequest(cert, issuer *Certificate, hash string) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("x509: ocsp: nil cert or issuer")
	}
	req, err := core.CreateOCSPRequest(cert.cert, issuer.cert, hash)
	if err != nil {
		return nil, err
	}
	defer req.Close()
	return req.MarshalDER()
}

// Response 表示解析后的 OCSP 响应。
// resp 持有底层响应（供 Verify），调用方负责 Close（Close 幂等）；
// Status 为响应级状态码（0=successful）；
// CertStatus 是目标证书状态（Good / Revoked / Unknown）；
// RevocationReason 为 -1 时表示无吊销原因；RevocationTime 未吊销时为零值。
//
// Response holds the decoded fields of one OCSP response. resp carries
// the underlying native handle used by Verify; the caller must invoke
// Close when the response is no longer needed (Close is idempotent and
// safe on a nil receiver). Status is the response-level status
// (0=successful); CertStatus is the target certificate status (Good /
// Revoked / Unknown). For Revoked responses RevocationTime and
// RevocationReason are populated; RevocationReason is -1 when no reason
// is supplied. ResponderCerts holds the certificates embedded in the
// response (signer chain).
type Response struct {
	resp *core.OCSPResponse // 持有底层响应（供 Verify），调用方负责 Close

	Status     int // 响应级状态码（0=successful）
	StatusText string
	ProducedAt time.Time

	CertStatus       int // 目标证书状态（OCSPGood / OCSPRevoked / OCSPUnknown）
	CertStatusText   string
	RevocationTime   time.Time // 吊销时间（未吊销为零值）
	RevocationReason int       // 吊销原因码（-1 无）
	ReasonText       string
	ThisUpdate       time.Time
	NextUpdate       time.Time

	ResponderCerts []*Certificate // 响应内证书（签名者链）
}

// ParseOCSPResponse 解析 OCSP 响应（DER），并查找 cert（由 issuer 签发）的状态。
// 返回的 Response 需调用 Close 释放。
// cert 与 issuer 均不得为 nil；响应级失败（Status != 0）时只填充响应级字段，
// CertStatus 保持零值。
//
// 原为 ocsp.ParseResponse（roadmap §3.10）。
//
// ParseOCSPResponse decodes a DER-encoded OCSP response and looks up the
// status of cert (issued by issuer). The returned *Response must be
// released with Close when no longer needed; Close is idempotent and
// safe on a nil receiver. Both cert and issuer must be non-nil. On a
// response-level failure (Status != 0) only the response-level fields are
// populated and CertStatus keeps its zero value.
//
// It was ocsp.ParseResponse (roadmap §3.10).
func ParseOCSPResponse(der []byte, cert, issuer *Certificate) (*Response, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("x509: ocsp: nil cert or issuer")
	}
	resp, err := core.LoadOCSPResponseDER(der)
	if err != nil {
		return nil, err
	}
	r := &Response{
		resp:       resp,
		Status:     resp.Status(),
		StatusText: resp.StatusText(),
		ProducedAt: resp.ProducedAt(),
	}
	if r.Status != 0 {
		return r, nil // 响应级失败，无证书状态
	}
	cs, err := resp.Check(cert.cert, issuer.cert)
	if err != nil {
		resp.Close()
		return nil, err
	}
	r.CertStatus = cs.Status
	r.CertStatusText = cs.StatusText
	r.RevocationTime = cs.RevocationTime
	r.RevocationReason = cs.ReasonCode
	r.ReasonText = cs.ReasonText
	r.ThisUpdate = cs.ThisUpdate
	r.NextUpdate = cs.NextUpdate
	if certs, err := resp.ResponderCerts(); err == nil {
		for _, c := range certs {
			wrapped, werr := wrapCertificate(c)
			if werr != nil {
				return nil, werr
			}
			r.ResponderCerts = append(r.ResponderCerts, wrapped)
		}
	}
	return r, nil
}

// Verify 验证响应签名；roots 为信任锚，intermediates 为中间证书（nil 时自动用响应内证书）；roots 必须非 nil，r.resp 必须未被 Close（否则返回 "response closed" 错误）。
//
// Verify checks the response signature against the X.509 chain. roots
// must be non-nil. r must not have been closed (otherwise an "ocsp:
// response closed" error is returned). When intermediates is nil the
// certificates embedded in the response are used as the intermediate
// chain.
func (r *Response) Verify(roots *Store, intermediates []*Certificate) error {
	if r == nil || r.resp == nil {
		return fmt.Errorf("x509: ocsp: response closed")
	}
	if roots == nil {
		return fmt.Errorf("x509: ocsp: nil trust store")
	}
	ccerts := make([]*core.Certificate, 0, len(intermediates))
	for _, c := range intermediates {
		if c != nil {
			ccerts = append(ccerts, c.cert)
		}
	}
	return r.resp.Verify(roots.store, ccerts)
}

// Close 释放底层响应（幂等），对 nil 接收者或已关闭的 Response 调用为安全 no-op。
//
// Close releases the underlying response. It is idempotent and safe to
// call on a nil receiver or on a Response that has already been closed
// (a no-op in both cases).
func (r *Response) Close() error {
	if r == nil || r.resp == nil {
		return nil
	}
	err := r.resp.Close()
	r.resp = nil
	return err
}
