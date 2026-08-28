package native

/*
#include <openssl/ocsp.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// OCSP_cert_to_id 构建证书 ID（md 如 EVP_sha1）。
func OCSP_cert_to_id(md, cert, issuer unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_cert_to_id((*C.EVP_MD)(md), (*C.X509)(cert), (*C.X509)(issuer)))
}

// OCSP_CERTID_free 释放证书 ID。
func OCSP_CERTID_free(cid unsafe.Pointer) {
	C.OCSP_CERTID_free((*C.OCSP_CERTID)(cid))
}

// OCSP_REQUEST_new 创建 OCSP 请求。
func OCSP_REQUEST_new() unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_REQUEST_new())
}

// OCSP_REQUEST_free 释放 OCSP 请求。
func OCSP_REQUEST_free(req unsafe.Pointer) {
	C.OCSP_REQUEST_free((*C.OCSP_REQUEST)(req))
}

// OCSP_request_add0_id 将证书 ID 加入请求（成功时转移 cid 所有权）。
func OCSP_request_add0_id(req, cid unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_request_add0_id((*C.OCSP_REQUEST)(req), (*C.OCSP_CERTID)(cid)))
}

// I2d_OCSP_REQUEST 将请求编码为 DER。
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
func OCSP_RESPONSE_free(resp unsafe.Pointer) {
	C.OCSP_RESPONSE_free((*C.OCSP_RESPONSE)(resp))
}

// OCSP_response_status 返回响应级状态码（0=successful）。
func OCSP_response_status(resp unsafe.Pointer) int {
	return int(C.OCSP_response_status((*C.OCSP_RESPONSE)(resp)))
}

// OCSP_response_status_str 返回响应级状态描述。
func OCSP_response_status_str(code int) string {
	c := C.OCSP_response_status_str(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// OCSP_response_get1_basic 提取 BasicOCSPResponse（返回新引用，调用方负责 OCSP_BASICRESP_free）。
func OCSP_response_get1_basic(resp unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_response_get1_basic((*C.OCSP_RESPONSE)(resp)))
}

// OCSP_BASICRESP_free 释放 BasicOCSPResponse。
func OCSP_BASICRESP_free(bs unsafe.Pointer) {
	C.OCSP_BASICRESP_free((*C.OCSP_BASICRESP)(bs))
}

// OCSP_resp_get0_produced_at 返回响应产生时间（unix 秒）。
func OCSP_resp_get0_produced_at(bs unsafe.Pointer) int64 {
	t := C.OCSP_resp_get0_produced_at((*C.OCSP_BASICRESP)(bs))
	if t == nil {
		return 0
	}
	return asn1TimeToUnix((*C.ASN1_TIME)(unsafe.Pointer(t)))
}

// OCSP_resp_get0_certs 返回响应内证书栈（内部指针，勿释放）。
func OCSP_resp_get0_certs(bs unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.OCSP_resp_get0_certs((*C.OCSP_BASICRESP)(bs)))
}

// OCSP_resp_find_status 查找证书 ID 的状态（good/revoked/unknown）。
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
func OCSP_basic_verify(bs, certsSk, store unsafe.Pointer, flags uint64) bool {
	return C.X_OCSP_basic_verify((*C.OCSP_BASICRESP)(bs), certsSk,
		(*C.X509_STORE)(store), C.ulong(flags)) == 1
}

// OCSP_cert_status_str 返回证书状态描述。
func OCSP_cert_status_str(code int) string {
	c := C.OCSP_cert_status_str(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// OCSP_crl_reason_str 返回吊销原因描述。
func OCSP_crl_reason_str(code int) string {
	c := C.OCSP_crl_reason_str(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}
