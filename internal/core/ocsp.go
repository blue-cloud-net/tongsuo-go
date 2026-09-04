package core

import (
	"fmt"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// OCSPRequest 表示 OCSP 请求（OCSP_REQUEST 的包装）。
// 通过内部 Handle 拥有底层 OCSP_REQUEST；调用方使用完毕后必须调用 Close 释放。
//
// OCSPRequest is the Go wrapper around an OpenSSL OCSP_REQUEST. It owns
// the underlying OCSP_REQUEST through an internal Handle; the caller
// MUST invoke Close to release it once they are done with the request.
type OCSPRequest struct {
	handle *Handle
}

// CreateOCSPRequest 创建对 cert（由 issuer 签发）的状态请求。
// hash 选择 issuer-name-hash / issuer-key-hash 摘要算法：
// "" 或 "sha1" 选 SHA-1，"sha256" 选 SHA-256，"sm3" 选 SM3；其他取值返回 "ocsp: unsupported hash %q"。
// 返回的 *OCSPRequest 拥有底层 OCSP_REQUEST；调用方必须调用 Close。
// 句柄为 nil 或已关闭时分别返回 "ocsp: invalid certificate" 或 "ocsp: invalid issuer"；底层 OpenSSL 调用失败包装为 OpError。
//
// CreateOCSPRequest builds an OCSP request for the certificate cert
// (issued by issuer). hash selects the issuer-name-hash / issuer-key-hash
// algorithm: "" or "sha1" selects SHA-1, "sha256" selects SHA-256,
// "sm3" selects SM3; any other value yields "ocsp: unsupported hash %q".
// The returned *OCSPRequest owns the underlying OCSP_REQUEST; the
// caller MUST invoke Close. Returns "ocsp: invalid certificate" or
// "ocsp: invalid issuer" when the corresponding handle is nil or
// already closed, or a wrapped OpError when the underlying OpenSSL
// calls fail.
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

// MarshalDER 编码请求为 DER（RFC 6960 定义的网络格式）。
// 请求已释放时返回 "ocsp: request closed"；底层 OpenSSL 失败包装为 OpError。
//
// MarshalDER serialises the OCSP request to DER (the wire format
// defined by RFC 6960). Returns "ocsp: request closed" when the
// request has been released; underlying OpenSSL failures are wrapped
// as OpError.
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
// nil 接收者返回 nil；Close 之后 MarshalDER 返回 "ocsp: request closed"。
//
// Close releases the underlying OCSP_REQUEST. The call is idempotent
// and returns nil on a nil receiver; after Close, MarshalDER returns
// "ocsp: request closed".
func (r *OCSPRequest) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}

// OCSPResponse 表示 OCSP 响应（OCSP_RESPONSE 的包装）。
// 通过内部 Handle 拥有底层 OCSP_RESPONSE；调用方使用完毕后必须调用 Close 释放。
//
// OCSPResponse is the Go wrapper around an OpenSSL OCSP_RESPONSE. It
// owns the underlying OCSP_RESPONSE through an internal Handle; the
// caller MUST invoke Close to release it once they are done with the
// response.
type OCSPResponse struct {
	handle *Handle
}

// LoadOCSPResponseDER 从 DER 加载响应（RFC 6960）。
// 返回的 *OCSPResponse 拥有底层 OCSP_RESPONSE；调用方必须调用 Close。
// 底层 OpenSSL 失败（DER 畸形、响应类型不受支持等）包装为 OpError。
//
// LoadOCSPResponseDER parses an OCSP response from its DER encoding
// (RFC 6960). The returned *OCSPResponse owns the underlying
// OCSP_RESPONSE; the caller MUST invoke Close. Underlying OpenSSL
// failures (malformed DER, unsupported response type) are wrapped as
// OpError.
func LoadOCSPResponseDER(der []byte) (*OCSPResponse, error) {
	p := native.D2i_OCSP_RESPONSE(der)
	if p == nil {
		return nil, NewOpError("ocsp: d2i_OCSP_RESPONSE", native.PopError())
	}
	return &OCSPResponse{handle: NewHandle(p, true, native.OCSP_RESPONSE_free)}, nil
}

// Status 返回响应级状态码（0 表示 successful）。
// 按 RFC 6960 §2.3，0 表示成功；其他值表示 malformedRequest、internalError、tryLater、sigRequired 或 unauthorized。
// nil 接收者或已释放的响应返回 -1。
//
// Status returns the response-level status code (0 means successful
// per RFC 6960 §2.3; other values indicate malformedRequest,
// internalError, tryLater, sigRequired or unauthorized). Returns -1
// on a nil receiver or an already-released response.
func (r *OCSPResponse) Status() int {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return -1
	}
	return native.OCSP_response_status(r.handle.Ptr())
}

// StatusText 返回响应级状态描述。
// 对应 Status 的人类可读描述（例如 "successful"、"internalError"、"tryLater"）；nil 接收者安全；底层调用使用 Status 的值。
//
// StatusText returns the human-readable description corresponding to
// Status (for example "successful", "internalError", "tryLater"). It
// is safe on a nil receiver; the underlying call uses the value
// produced by Status.
func (r *OCSPResponse) StatusText() string {
	return native.OCSP_response_status_str(r.Status())
}

// CertStatus 表示证书在响应中的状态。
// 由 OCSPResponse.Check 从 OCSP 响应中解码；Status / ReasonCode 取值遵循 RFC 6960 枚举；未吊销时 RevocationTime 为零值时间。
//
// CertStatus is the per-certificate status decoded from an OCSP
// response by OCSPResponse.Check. The Status / ReasonCode values
// follow the RFC 6960 enumerations; RevocationTime is the zero time
// when the certificate is not revoked.
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
// 响应级 Status 必须为 0（successful），其他值返回 "ocsp: response status <n> (<text>)"。
// 响应已释放返回 "ocsp: response closed"；句柄为 nil 或已关闭返回 "ocsp: invalid cert or issuer"；
// 未找到匹配的 CertID 返回 "ocsp: no status for certificate"；底层 OpenSSL 调用失败包装为 OpError。
// 返回的 CertStatus 从响应填充 StatusText、ReasonText、ThisUpdate、NextUpdate；RevocationTime 仅在 Status == revoked 时设置。
//
// 匹配采用自适应策略（D3）：依次尝试 sha1 / sha256 / sm3 三种摘要重算
// CertID（请求支持集），因此与 CreateOCSPRequest 任一所选 hash 构造的请求
// 都能匹配其响应；离线解析（无请求上下文）同样成立。
//
// Check decodes the per-certificate entry matching cert / issuer in the
// response. The response-level Status MUST be 0 (successful); any other
// value yields "ocsp: response status <n> (<text>)". Returns
// "ocsp: response closed" when the response has been released,
// "ocsp: invalid cert or issuer" for nil / closed handles,
// "ocsp: no status for certificate" when no matching CertID is found,
// or a wrapped OpError when the underlying OpenSSL calls fail. The
// returned CertStatus has StatusText, ReasonText, ThisUpdate and
// NextUpdate populated from the response; RevocationTime is set only
// when Status == revoked.
//
// Matching is adaptive (D3): sha1 / sha256 / sm3 are tried in turn to
// rebuild the CertID, so responses to any hash accepted by
// CreateOCSPRequest match, and offline parsing (without the request
// context) works too.
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
	// 自适应 CertID 匹配（D3）：请求支持 sha1/sha256/sm3（CreateOCSPRequest），
	// 响应中的 CertID 由请求所用 hash 决定。这里依次用三种摘要重算
	// issuerNameHash/issuerKeyHash 尝试匹配，任何命中即视为找到该证书状态。
	// 这样既支持离线解析（无请求上下文），也消除 sha256/sm3 请求的"死路"。
	for _, md := range []*Digest{SHA1(), SHA256(), SM3()} {
		cid := native.OCSP_cert_to_id(md.handle.Ptr(), cert.handle.Ptr(), issuer.handle.Ptr())
		if cid == nil {
			continue
		}
		found, status, reason, revTime, thisUpdate, nextUpdate := native.OCSP_resp_find_status(basic, cid)
		native.OCSP_CERTID_free(cid)
		if !found {
			continue
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
	return nil, fmt.Errorf("ocsp: no status for certificate")
}

// ProducedAt 返回响应产生时间（RFC 6960 producedAt，响应方对响应签名的时间）。
// nil 接收者或响应已释放 / 找不到 basic 响应时返回零值时间。
//
// ProducedAt returns the time at which the responder signed the
// response (RFC 6960 producedAt). Returns the zero Time on a nil
// receiver or when the response has been released / the basic
// response cannot be located.
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

// ResponderCerts 返回响应内证书（响应方签名链，每项为复制的 X509）。
// 每个返回的 *Certificate 拥有独立复制的 X509 句柄，调用方负责对每个条目调用 Close。
// 响应不含证书时返回 nil（与 nil 错误）；响应已释放时返回 "ocsp: response closed"；底层 OpenSSL 失败包装为 OpError。
//
// ResponderCerts returns the certificates embedded inside the OCSP
// response (the responder's signing chain). Each returned
// *Certificate owns a freshly duplicated X509 handle; the caller is
// responsible for invoking Close on every entry. Returns nil (and a
// nil error) when the response contains no certificates.
// "ocsp: response closed" is returned when the response has been
// released; underlying OpenSSL failures are wrapped as OpError.
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
// 响应内证书的 Close 由本方法自动调度；调用方仍拥有其自行传入的 certs 切片。
// 响应已释放返回 "ocsp: response closed"；roots 为 nil 或已关闭返回 "ocsp: invalid trust store"；
// OCSP_basic_verify 报告签名 / 链失败时包装为 OpError。
//
// Verify validates the signature on the OCSP response. roots is the
// trust anchor store used to verify the responder certificate; certs
// supplies intermediate certificates and may be nil, in which case
// the certificates embedded in the response itself are used (their
// Close is scheduled automatically — the caller still owns the
// caller-supplied slice). Returns "ocsp: response closed" when the
// response has been released, "ocsp: invalid trust store" when roots
// is nil or closed, or a wrapped OpError when OCSP_basic_verify
// reports a signature / chain failure.
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
// nil 接收者返回 nil；Close 之后所有其他方法返回 "ocsp: response closed"。
//
// Close releases the underlying OCSP_RESPONSE. The call is idempotent
// and returns nil on a nil receiver; after Close all other methods on
// the receiver return "ocsp: response closed".
func (r *OCSPResponse) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}
