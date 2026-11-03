package core

import (
	"fmt"
	"runtime"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// LoadOCSPRequestDER 解析请求；调用方负责 Close。
//
// LoadOCSPRequestDER parses a request; callers must Close it.
func LoadOCSPRequestDER(data []byte) (*OCSPRequest, error) {
	p := native.D2i_OCSP_REQUEST(data)
	if p == nil {
		return nil, NewOpError("ocsp: parse request", native.PopError())
	}
	return &OCSPRequest{handle: NewHandle(p, true, native.OCSP_REQUEST_free)}, nil
}

// AddNonce 向请求复制 1..32 字节 nonce；已关闭请求返回错误。
//
// AddNonce copies a 1..32-byte nonce into the request; closed requests return errors.
func (r *OCSPRequest) AddNonce(nonce []byte) error {
	defer runtime.KeepAlive(r)
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return fmt.Errorf("ocsp: request closed")
	}
	if len(nonce) < 1 || len(nonce) > 32 {
		return fmt.Errorf("ocsp: nonce length must be 1..32")
	}
	if !native.OCSP_request_add1_nonce(r.handle.Ptr(), nonce) {
		return NewOpError("ocsp: add nonce", native.PopError())
	}
	return nil
}

// CheckNonce 校验请求 nonce；缺失或不匹配均返回错误。
//
// CheckNonce checks the request nonce; missing or mismatched response nonces return errors.
func (r *OCSPResponse) CheckNonce(req *OCSPRequest) error {
	defer runtime.KeepAlive(r)
	defer runtime.KeepAlive(req)
	if r == nil || r.handle == nil || r.handle.IsClosed() || req == nil || req.handle == nil || req.handle.IsClosed() {
		return fmt.Errorf("ocsp: request or response closed")
	}
	n := native.OCSP_check_nonce(req.handle.Ptr(), r.handle.Ptr())
	if n != 1 && n != 2 && n != 3 {
		return fmt.Errorf("ocsp: missing or mismatched nonce")
	}
	return nil
}

// CheckRequest 获取单证书请求的响应状态；不匹配与多证书请求返回错误。
//
// CheckRequest gets the response status for a single-certificate request; unmatched or multiple requests return errors.
func (r *OCSPResponse) CheckRequest(req *OCSPRequest) (*CertStatus, error) {
	defer runtime.KeepAlive(r)
	defer runtime.KeepAlive(req)
	if r == nil || r.handle == nil || r.handle.IsClosed() || req == nil || req.handle == nil || req.handle.IsClosed() {
		return nil, fmt.Errorf("ocsp: request or response closed")
	}
	if r.Status() != 0 {
		return nil, fmt.Errorf("ocsp: response status %d", r.Status())
	}
	id := native.X_OCSP_request_get0_id(req.handle.Ptr())
	if id == nil {
		return nil, fmt.Errorf("ocsp: expected one certificate in request")
	}
	basic := native.OCSP_response_get1_basic(r.handle.Ptr())
	if basic == nil {
		return nil, NewOpError("ocsp: basic response", native.PopError())
	}
	defer native.OCSP_BASICRESP_free(basic)
	found, status, reason, rev, this, next := native.OCSP_resp_find_status(basic, id)
	if !found {
		return nil, fmt.Errorf("ocsp: no status for request")
	}
	s := &CertStatus{Status: status, StatusText: native.OCSP_cert_status_str(status), ReasonCode: reason, ReasonText: native.OCSP_crl_reason_str(reason)}
	if rev != 0 {
		s.RevocationTime = time.Unix(rev, 0).UTC()
	}
	if this != 0 {
		s.ThisUpdate = time.Unix(this, 0).UTC()
	}
	if next != 0 {
		s.NextUpdate = time.Unix(next, 0).UTC()
	}
	return s, nil
}
