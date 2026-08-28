package core

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// OCSPRequest 表示 OCSP 请求（OCSP_REQUEST 的包装）。
type OCSPRequest struct {
	handle *Handle
}

// CreateOCSPRequest 创建对 cert（由 issuer 签发）的状态请求。
// hash 取 "sha1" / "sha256" / "sm3"，空为 sha1。
func CreateOCSPRequest(cert, issuer *Certificate, hash string) (*OCSPRequest, error) {
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return nil, fmt.Errorf("ocsp: invalid certificate")
	}
	if issuer == nil || issuer.handle == nil || issuer.handle.IsClosed() {
		return nil, fmt.Errorf("ocsp: invalid issuer")
	}
	var md *Digest
	switch hash {
	case "", "sha1":
		md = SHA1()
	case "sha256":
		md = SHA256()
	case "sm3":
		md = SM3()
	default:
		return nil, fmt.Errorf("ocsp: unsupported hash %q", hash)
	}
	cid := native.OCSP_cert_to_id(md.handle.Ptr(), cert.handle.Ptr(), issuer.handle.Ptr())
	if cid == nil {
		return nil, NewOpError("ocsp: OCSP_cert_to_id", native.PopError())
	}
	req := native.OCSP_REQUEST_new()
	if req == nil {
		native.OCSP_CERTID_free(cid)
		return nil, NewOpError("ocsp: OCSP_REQUEST_new", native.PopError())
	}
	h := NewHandle(req, true, native.OCSP_REQUEST_free)
	if native.OCSP_request_add0_id(req, cid) == nil { // 成功时转移 cid 所有权
		_ = h.Close()
		native.OCSP_CERTID_free(cid)
		return nil, NewOpError("ocsp: OCSP_request_add0_id", native.PopError())
	}
	return &OCSPRequest{handle: h}, nil
}

// MarshalDER 编码请求为 DER。
func (r *OCSPRequest) MarshalDER() ([]byte, error) {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil, fmt.Errorf("ocsp: request closed")
	}
	der, ok := native.I2d_OCSP_REQUEST(r.handle.Ptr())
	if !ok {
		return nil, NewOpError("ocsp: i2d_OCSP_REQUEST", native.PopError())
	}
	return der, nil
}

// Close 释放请求。幂等。
func (r *OCSPRequest) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}

// OCSPResponse 表示 OCSP 响应（OCSP_RESPONSE 的包装）。
type OCSPResponse struct {
	handle *Handle
}

// LoadOCSPResponseDER 从 DER 加载响应。
func LoadOCSPResponseDER(der []byte) (*OCSPResponse, error) {
	p := native.D2i_OCSP_RESPONSE(der)
	if p == nil {
		return nil, NewOpError("ocsp: d2i_OCSP_RESPONSE", native.PopError())
	}
	return &OCSPResponse{handle: NewHandle(p, true, native.OCSP_RESPONSE_free)}, nil
}

// Status 返回响应级状态码（0=successful）。
func (r *OCSPResponse) Status() int {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return -1
	}
	return native.OCSP_response_status(r.handle.Ptr())
}

// StatusText 返回响应级状态描述。
func (r *OCSPResponse) StatusText() string {
	return native.OCSP_response_status_str(r.Status())
}

// CertStatus 表示证书在响应中的状态。
type CertStatus struct {
	Status         int       // 0=good, 1=revoked, 2=unknown
	StatusText     string    // 状态描述
	RevocationTime time.Time // 吊销时间（未吊销为零值）
	ReasonCode     int       // 吊销原因码（-1 无）
	ReasonText     string
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

// Check 检查 cert（由 issuer 签发）在响应中的状态。
func (r *OCSPResponse) Check(cert, issuer *Certificate) (*CertStatus, error) {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil, fmt.Errorf("ocsp: response closed")
	}
	if r.Status() != 0 {
		return nil, fmt.Errorf("ocsp: response status %d (%s)", r.Status(), r.StatusText())
	}
	if cert == nil || issuer == nil || cert.handle == nil || issuer.handle == nil {
		return nil, fmt.Errorf("ocsp: invalid cert or issuer")
	}
	basic := native.OCSP_response_get1_basic(r.handle.Ptr())
	if basic == nil {
		return nil, NewOpError("ocsp: OCSP_response_get1_basic", native.PopError())
	}
	defer native.OCSP_BASICRESP_free(basic)
	cid := native.OCSP_cert_to_id(native.EVP_sha1(), cert.handle.Ptr(), issuer.handle.Ptr())
	if cid == nil {
		return nil, NewOpError("ocsp: OCSP_cert_to_id", native.PopError())
	}
	defer native.OCSP_CERTID_free(cid)
	found, status, reason, revTime, thisUpdate, nextUpdate := native.OCSP_resp_find_status(basic, cid)
	if !found {
		return nil, fmt.Errorf("ocsp: no status for certificate")
	}
	st := &CertStatus{
		Status:     status,
		StatusText: native.OCSP_cert_status_str(status),
		ReasonCode: reason,
		ReasonText: native.OCSP_crl_reason_str(reason),
		ThisUpdate: time.Unix(thisUpdate, 0).UTC(),
		NextUpdate: time.Unix(nextUpdate, 0).UTC(),
	}
	if status == 1 && revTime != 0 {
		st.RevocationTime = time.Unix(revTime, 0).UTC()
	}
	return st, nil
}

// ProducedAt 返回响应产生时间。
func (r *OCSPResponse) ProducedAt() time.Time {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return time.Time{}
	}
	basic := native.OCSP_response_get1_basic(r.handle.Ptr())
	if basic == nil {
		return time.Time{}
	}
	defer native.OCSP_BASICRESP_free(basic)
	return time.Unix(native.OCSP_resp_get0_produced_at(basic), 0).UTC()
}

// ResponderCerts 返回响应内证书（签名者链，复制）。
func (r *OCSPResponse) ResponderCerts() ([]*Certificate, error) {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil, fmt.Errorf("ocsp: response closed")
	}
	basic := native.OCSP_response_get1_basic(r.handle.Ptr())
	if basic == nil {
		return nil, NewOpError("ocsp: OCSP_response_get1_basic", native.PopError())
	}
	defer native.OCSP_BASICRESP_free(basic)
	sk := native.OCSP_resp_get0_certs(basic)
	if sk == nil {
		return nil, nil
	}
	count := native.X509_sk_X509_num(sk)
	out := make([]*Certificate, 0, count)
	for i := 0; i < count; i++ {
		x := native.X509_sk_X509_value(sk, i)
		if x == nil {
			continue
		}
		dup := native.X509_dup(x)
		if dup == nil {
			continue
		}
		out = append(out, &Certificate{handle: NewHandle(dup, true, native.X509_free)})
	}
	return out, nil
}

// Verify 验证响应签名。roots 为信任锚；certs 为中间证书（nil 时自动用响应内证书）。
func (r *OCSPResponse) Verify(roots *Store, certs []*Certificate) error {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return fmt.Errorf("ocsp: response closed")
	}
	if roots == nil || roots.handle == nil || roots.handle.IsClosed() {
		return fmt.Errorf("ocsp: invalid trust store")
	}
	basic := native.OCSP_response_get1_basic(r.handle.Ptr())
	if basic == nil {
		return NewOpError("ocsp: OCSP_response_get1_basic", native.PopError())
	}
	defer native.OCSP_BASICRESP_free(basic)
	sk := native.X509_sk_X509_new_null()
	if sk == nil {
		return NewOpError("ocsp: sk_X509_new_null", native.PopError())
	}
	defer native.X509_sk_X509_free(sk)
	if len(certs) == 0 {
		respCerts, err := r.ResponderCerts()
		if err != nil {
			return err
		}
		for _, c := range respCerts {
			defer c.Close()
		}
		certs = respCerts
	}
	for _, c := range certs {
		if c != nil && c.handle != nil && !c.handle.IsClosed() {
			native.X509_sk_X509_push(sk, c.handle.Ptr())
		}
	}
	if !native.OCSP_basic_verify(basic, sk, roots.handle.Ptr(), 0) {
		return NewOpError("ocsp: OCSP_basic_verify", native.PopError())
	}
	return nil
}

// Close 释放响应。幂等。
func (r *OCSPResponse) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}
