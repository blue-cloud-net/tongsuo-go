package native

/*
#include <openssl/ocsp.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// D2i_OCSP_REQUEST 解析 DER 请求，返回拥有的指针。
//
// D2i_OCSP_REQUEST parses a DER request and returns an owned pointer.
func D2i_OCSP_REQUEST(data []byte) unsafe.Pointer {
	if len(data) == 0 {
		return nil
	}
	buf := C.CBytes(data)
	if buf == nil {
		return nil
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	return unsafe.Pointer(C.d2i_OCSP_REQUEST(nil, &p, C.long(len(data))))
}

// OCSP_request_add1_nonce 复制 nonce 到请求。
//
// OCSP_request_add1_nonce copies the nonce into the request.
func OCSP_request_add1_nonce(req unsafe.Pointer, nonce []byte) bool {
	if len(nonce) == 0 {
		return false
	}
	return C.OCSP_request_add1_nonce((*C.OCSP_REQUEST)(req), (*C.uchar)(unsafe.Pointer(&nonce[0])), C.int(len(nonce))) == 1
}

// OCSP_check_nonce 比较请求与响应的 nonce，返回原生状态码。
//
// OCSP_check_nonce compares request/response nonces and returns the native status.
func OCSP_check_nonce(req, resp unsafe.Pointer) int {
	basic := C.OCSP_response_get1_basic((*C.OCSP_RESPONSE)(resp))
	if basic == nil {
		return 0
	}
	defer C.OCSP_BASICRESP_free(basic)
	return int(C.OCSP_check_nonce((*C.OCSP_REQUEST)(req), basic))
}

// X_OCSP_request_get0_id 返回单证书请求中的借用 CertID，其他请求返回 nil。
//
// X_OCSP_request_get0_id returns a borrowed CertID for a single-certificate request, or nil.
func X_OCSP_request_get0_id(req unsafe.Pointer) unsafe.Pointer {
	q := (*C.OCSP_REQUEST)(req)
	if C.OCSP_request_onereq_count(q) != 1 {
		return nil
	}
	return unsafe.Pointer(C.OCSP_onereq_get0_id(C.OCSP_request_onereq_get0(q, 0)))
}
