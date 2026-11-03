package x509

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

const maxOCSPResponse = 4 << 20

// CreateOCSPRequestWithNonce 构造带 nonce 的单证书请求；nil nonce 生成 32 字节随机值。
// 非 nil nonce 必须为 1..32 字节；失败返回错误。
//
// CreateOCSPRequestWithNonce builds a single-certificate request with a nonce; nil generates 32 random bytes.
// A non-nil nonce must contain 1..32 bytes; failures return errors.
func CreateOCSPRequestWithNonce(cert, issuer *Certificate, hash string, nonce []byte) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("x509: ocsp: nil cert or issuer")
	}
	if nonce == nil {
		nonce = make([]byte, 32)
		err := core.RandomBytes(nonce)
		if err != nil {
			return nil, err
		}
	}
	req, err := core.CreateOCSPRequest(cert.cert, issuer.cert, hash)
	if err != nil {
		return nil, err
	}
	defer req.Close()
	if err = req.AddNonce(nonce); err != nil {
		return nil, err
	}
	return req.MarshalDER()
}

// CheckNonce 比较响应与 DER 请求中的 nonce，缺失或不匹配返回错误。
// 此操作不验证响应签名；须另行调用 Verify。
//
// CheckNonce compares the response nonce against a DER request; a missing or mismatched nonce returns an error.
// It does not verify the response signature; call Verify separately.
func (r *Response) CheckNonce(request []byte) error {
	if r == nil || r.resp == nil {
		return fmt.Errorf("x509: ocsp: response closed")
	}
	req, err := core.LoadOCSPRequestDER(request)
	if err != nil {
		return err
	}
	defer req.Close()
	return r.resp.CheckNonce(req)
}

// FetchOCSP 通过 HTTP POST 发送单证书 DER 请求，解析状态并校验 nonce。
// timeout 为 0 时使用 10 秒，负值无效；响应限制为 4 MiB，不跟随重定向。
// 返回响应须 Close，并须另行 Verify 签名及检查 ThisUpdate/NextUpdate 后才能信任状态。
//
// FetchOCSP posts a single-certificate DER request over HTTP, parses status and checks the nonce.
// A zero timeout selects 10 seconds; negative values are invalid. Responses are limited to 4 MiB; redirects are rejected.
// Close the response and Verify its signature and ThisUpdate/NextUpdate before trusting the status.
func FetchOCSP(url string, request []byte, timeout time.Duration) (*Response, error) {
	if timeout < 0 {
		return nil, fmt.Errorf("x509: ocsp: negative timeout")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	q, err := core.LoadOCSPRequestDER(request)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("x509: ocsp: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("x509: ocsp: fetch: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("x509: ocsp: HTTP status %d", res.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mt != "application/ocsp-response" {
		return nil, fmt.Errorf("x509: ocsp: invalid response content type")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxOCSPResponse+1))
	if err != nil {
		return nil, fmt.Errorf("x509: ocsp: read: %w", err)
	}
	if len(data) > maxOCSPResponse {
		return nil, fmt.Errorf("x509: ocsp: response too large")
	}
	resp, err := core.LoadOCSPResponseDER(data)
	if err != nil {
		return nil, err
	}
	r := &Response{resp: resp, Status: resp.Status(), StatusText: resp.StatusText(), ProducedAt: resp.ProducedAt()}
	if r.Status != 0 {
		return r, nil
	}
	if err = resp.CheckNonce(q); err != nil {
		r.Close()
		return nil, err
	}
	cs, err := resp.CheckRequest(q)
	if err != nil {
		r.Close()
		return nil, err
	}
	r.CertStatus = cs.Status
	r.CertStatusText = cs.StatusText
	r.RevocationTime = cs.RevocationTime
	r.RevocationReason = cs.ReasonCode
	r.ReasonText = cs.ReasonText
	r.ThisUpdate = cs.ThisUpdate
	r.NextUpdate = cs.NextUpdate
	certs, err := resp.ResponderCerts()
	if err != nil {
		r.Close()
		return nil, err
	}
	for i, c := range certs {
		wrapped, e := wrapCertificate(c)
		c.Close()
		if e != nil {
			for _, remaining := range certs[i:] {
				remaining.Close()
			}
			for _, done := range r.ResponderCerts {
				done.Close()
			}
			r.Close()
			return nil, e
		}
		r.ResponderCerts = append(r.ResponderCerts, wrapped)
	}
	return r, nil
}
