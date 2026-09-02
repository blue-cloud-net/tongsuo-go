package native

/*
#include <openssl/ocsp.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// OCSP_cert_to_id 构建证书 ID（md 如 EVP_sha1）。
//
// OCSP_cert_to_id builds an OCSP_CERTID for cert, hashed under md, against
// issuer. The caller owns the returned OCSP_CERTID and must release it with
// OCSP_CERTID_free.
func OCSP_cert_to_id(md, cert, issuer unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_cert_to_id((*C.EVP_MD)(md), (*C.X509)(cert), (*C.X509)(issuer)))
}

// OCSP_CERTID_free 释放证书 ID。
//
// OCSP_CERTID_free releases the OCSP_CERTID. Safe on NULL; the pointer must
// not be used after free.
func OCSP_CERTID_free(cid unsafe.Pointer) {
	C.OCSP_CERTID_free((*C.OCSP_CERTID)(cid))
}

// OCSP_REQUEST_new 创建 OCSP 请求。
//
// OCSP_REQUEST_new allocates a new empty OCSP_REQUEST. The caller owns the
// returned pointer and must release it with OCSP_REQUEST_free.
func OCSP_REQUEST_new() unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_REQUEST_new())
}

// OCSP_REQUEST_free 释放 OCSP 请求。
//
// OCSP_REQUEST_free releases the OCSP_REQUEST. Safe on NULL; the pointer must
// not be used after free.
func OCSP_REQUEST_free(req unsafe.Pointer) {
	C.OCSP_REQUEST_free((*C.OCSP_REQUEST)(req))
}

// OCSP_request_add0_id 将证书 ID 加入请求（成功时转移 cid 所有权）。
//
// OCSP_request_add0_id appends cid to req. On success ownership of cid is
// transferred to req; the caller must NOT free cid separately.
func OCSP_request_add0_id(req, cid unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_request_add0_id((*C.OCSP_REQUEST)(req), (*C.OCSP_CERTID)(cid)))
}

// I2d_OCSP_REQUEST 将请求编码为 DER。
//
// I2d_OCSP_REQUEST serializes req to DER. Returns (bytes, true) on success
// or (nil, false) when the OpenSSL encoder reports a non-positive length.
func I2d_OCSP_REQUEST(req unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_OCSP_REQUEST((*C.OCSP_REQUEST)(req), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_OCSP_REQUEST((*C.OCSP_REQUEST)(req), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// D2i_OCSP_RESPONSE 从 DER 解析 OCSP 响应。
//
// D2i_OCSP_RESPONSE parses an OCSP_RESPONSE from the given DER bytes. Returns
// NULL on empty input or parse failure. The caller owns the result and must
// release it with OCSP_RESPONSE_free.
func D2i_OCSP_RESPONSE(der []byte) unsafe.Pointer {
	if len(der) == 0 {
		return nil
	}
	buf := C.malloc(C.size_t(len(der)))
	if buf == nil {
		return nil
	}
	defer C.free(buf)
	C.memcpy(buf, unsafe.Pointer(&der[0]), C.size_t(len(der)))
	p := (*C.uchar)(buf)
	return unsafe.Pointer(C.d2i_OCSP_RESPONSE(nil, &p, C.long(len(der))))
}

// OCSP_RESPONSE_free 释放响应。
//
// OCSP_RESPONSE_free releases the OCSP_RESPONSE. Safe on NULL; the pointer
// must not be used after free.
func OCSP_RESPONSE_free(resp unsafe.Pointer) {
	C.OCSP_RESPONSE_free((*C.OCSP_RESPONSE)(resp))
}

// OCSP_response_status 返回响应级状态码（0=successful）。
//
// OCSP_response_status returns the top-level response status of resp
// (0 == OCSP_RESPONSE_STATUS_SUCCESSFUL).
func OCSP_response_status(resp unsafe.Pointer) int {
	return int(C.OCSP_response_status((*C.OCSP_RESPONSE)(resp)))
}

// OCSP_response_status_str 返回响应级状态描述。
//
// OCSP_response_status_str returns the human-readable description for a
// top-level OCSP response status code, or "" when the C string is NULL.
func OCSP_response_status_str(code int) string {
	c := C.OCSP_response_status_str(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// OCSP_response_get1_basic 提取 BasicOCSPResponse（返回新引用，调用方负责 OCSP_BASICRESP_free）。
//
// OCSP_response_get1_basic extracts the BasicOCSPResponse from resp. The
// caller owns the returned reference and must release it with
// OCSP_BASICRESP_free.
func OCSP_response_get1_basic(resp unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_response_get1_basic((*C.OCSP_RESPONSE)(resp)))
}

// OCSP_BASICRESP_free 释放 BasicOCSPResponse。
//
// OCSP_BASICRESP_free releases the OCSP_BASICRESP. Safe on NULL; the pointer
// must not be used after free.
func OCSP_BASICRESP_free(bs unsafe.Pointer) {
	C.OCSP_BASICRESP_free((*C.OCSP_BASICRESP)(bs))
}

// OCSP_resp_get0_produced_at 返回响应产生时间（unix 秒）。
//
// OCSP_resp_get0_produced_at returns the time the BasicOCSPResponse was
// produced, in unix seconds. Returns 0 when the field is unset.
func OCSP_resp_get0_produced_at(bs unsafe.Pointer) int64 {
	t := C.OCSP_resp_get0_produced_at((*C.OCSP_BASICRESP)(bs))
	if t == nil {
		return 0
	}
	return asn1TimeToUnix((*C.ASN1_TIME)(unsafe.Pointer(t)))
}

// OCSP_resp_get0_certs 返回响应内证书栈（内部指针，勿释放）。
//
// OCSP_resp_get0_certs returns the internal stack of certificates embedded
// in the BasicOCSPResponse. The pointer is owned by bs and must NOT be freed.
func OCSP_resp_get0_certs(bs unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_resp_get0_certs((*C.OCSP_BASICRESP)(bs)))
}

// OCSP_resp_find_status 查找证书 ID 的状态（good/revoked/unknown）。
//
// OCSP_resp_find_status looks up the certificate status entry for cid inside
// bs. It returns (found, status, reason, revocationTime, thisUpdate,
// nextUpdate). Times are unix seconds, 0 when not set.
func OCSP_resp_find_status(bs, cid unsafe.Pointer) (found bool, status, reason int, revTime, thisUpdate, nextUpdate int64) {
	var s, r C.int
	var rev, thisu, nextu *C.ASN1_GENERALIZEDTIME
	f := C.OCSP_resp_find_status((*C.OCSP_BASICRESP)(bs), (*C.OCSP_CERTID)(cid),
		&s, &r, &rev, &thisu, &nextu)
	if rev != nil {
		revTime = asn1TimeToUnix((*C.ASN1_TIME)(unsafe.Pointer(rev)))
	}
	if thisu != nil {
		thisUpdate = asn1TimeToUnix((*C.ASN1_TIME)(unsafe.Pointer(thisu)))
	}
	if nextu != nil {
		nextUpdate = asn1TimeToUnix((*C.ASN1_TIME)(unsafe.Pointer(nextu)))
	}
	return f == 1, int(s), int(r), revTime, thisUpdate, nextUpdate
}

// OCSP_basic_verify 验证响应签名（certs 为响应证书/中间证书栈，store 为信任锚）。
//
// OCSP_basic_verify verifies the BasicOCSPResponse signature using certsSk
// (response / intermediate cert stack) and store as trust anchor.
func OCSP_basic_verify(bs, certsSk, store unsafe.Pointer, flags uint64) bool {
	return C.X_OCSP_basic_verify((*C.OCSP_BASICRESP)(bs), certsSk,
		(*C.X509_STORE)(store), C.ulong(flags)) == 1
}

// OCSP_cert_status_str 返回证书状态描述。
//
// OCSP_cert_status_str returns the description for a per-certificate status
// code (0=good, 1=revoked, 2=unknown), or "" when the C string is NULL.
func OCSP_cert_status_str(code int) string {
	c := C.OCSP_cert_status_str(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// OCSP_crl_reason_str 返回吊销原因描述。
//
// OCSP_crl_reason_str returns the description for a CRL reason code
// (keyCompromise, caCompromise, etc.), or "" when the C string is NULL.
func OCSP_crl_reason_str(code int) string {
	c := C.OCSP_crl_reason_str(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}
