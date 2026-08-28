// Package ocsp 基于铜锁原生实现实现 OCSP（在线证书状态协议）。
//
// 提供请求构造（CreateRequest）、响应解析（ParseResponse）与响应签名验证（Verify，
// 复用 X.509 链验证）。证书状态：0=good，1=revoked，2=unknown。
package ocsp

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/x509"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// 证书状态码（OCSP CertStatus）。
const (
	Good    = 0
	Revoked = 1
	Unknown = 2
)

// CreateRequest 生成对 cert（由 issuer 签发）的 OCSP 状态请求（DER）。
// hash 取 "sha1" / "sha256" / "sm3"，空为 sha1。
func CreateRequest(cert, issuer *x509.Certificate, hash string) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("ocsp: nil cert or issuer")
	}
	req, err := core.CreateOCSPRequest(cert.Core(), issuer.Core(), hash)
	if err != nil {
		return nil, err
	}
	defer req.Close()
	return req.MarshalDER()
}

// Response 表示解析后的 OCSP 响应。
type Response struct {
	resp *core.OCSPResponse // 持有底层响应（供 Verify），调用方负责 Close

	Status     int // 响应级状态码（0=successful）
	StatusText string
	ProducedAt time.Time

	CertStatus       int // 目标证书状态（Good / Revoked / Unknown）
	CertStatusText   string
	RevocationTime   time.Time // 吊销时间（未吊销为零值）
	RevocationReason int       // 吊销原因码（-1 无）
	ReasonText       string
	ThisUpdate       time.Time
	NextUpdate       time.Time

	ResponderCerts []*x509.Certificate // 响应内证书（签名者链）
}

// ParseResponse 解析 OCSP 响应（DER），并查找 cert（由 issuer 签发）的状态。
// 返回的 Response 需调用 Close 释放。
func ParseResponse(der []byte, cert, issuer *x509.Certificate) (*Response, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("ocsp: nil cert or issuer")
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
	cs, err := resp.Check(cert.Core(), issuer.Core())
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
			r.ResponderCerts = append(r.ResponderCerts, x509.WrapCertificate(c))
		}
	}
	return r, nil
}

// Verify 验证响应签名。roots 为信任锚；intermediates 为中间证书（nil 时自动用响应内证书）。
func (r *Response) Verify(roots *x509.Store, intermediates []*x509.Certificate) error {
	if r == nil || r.resp == nil {
		return fmt.Errorf("ocsp: response closed")
	}
	if roots == nil {
		return fmt.Errorf("ocsp: nil trust store")
	}
	ccerts := make([]*core.Certificate, 0, len(intermediates))
	for _, c := range intermediates {
		if c != nil {
			ccerts = append(ccerts, c.Core())
		}
	}
	return r.resp.Verify(roots.Core(), ccerts)
}

// Close 释放底层响应。幂等。
func (r *Response) Close() error {
	if r == nil || r.resp == nil {
		return nil
	}
	err := r.resp.Close()
	r.resp = nil
	return err
}
