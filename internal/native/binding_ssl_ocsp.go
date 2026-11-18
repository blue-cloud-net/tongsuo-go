package native

/*
#include <openssl/ssl.h>

static int request_ocsp(SSL *s) {
    return SSL_set_tlsext_status_type(s, TLSEXT_STATUSTYPE_ocsp);
}

static int set_ocsp(SSL *s, const unsigned char *der, int len) {
    unsigned char *copy = OPENSSL_memdup(der, len);
    if (!copy) return 0;
    if (SSL_set_tlsext_status_ocsp_resp(s, copy, len) == 1) return 1;
    OPENSSL_free(copy);
    return 0;
}

static long read_ocsp(SSL *s, unsigned char **out) {
    return SSL_get_tlsext_status_ocsp_resp(s, out);
}
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"
)

// X_SSL_request_ocsp 配置客户端请求 OCSP 装订。
//
// X_SSL_request_ocsp enables client OCSP stapling requests.
func X_SSL_request_ocsp(ssl unsafe.Pointer) bool {
	return C.request_ocsp((*C.SSL)(ssl)) == 1
}

// X_SSL_read_ocsp 复制连接持有的响应。
//
// X_SSL_read_ocsp copies the response owned by the connection.
func X_SSL_read_ocsp(ssl unsafe.Pointer) []byte {
	var ptr *C.uchar
	n := C.read_ocsp((*C.SSL)(ssl), &ptr)
	if n <= 0 || ptr == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(n))
}

// CgoTLSStaple 安装当前证书的装订响应。
// CgoTLSStaple installs the response for the selected certificate.
//
//export CgoTLSStaple
func CgoTLSStaple(id C.uintptr_t, ssl *C.SSL) C.int {
	cb := cgo.Handle(id).Value().(*TLSCallbacks)
	if cb.Staple == nil {
		return C.SSL_TLSEXT_ERR_NOACK
	}
	der, err := cb.Staple(certificateDER(C.SSL_get_certificate(ssl)))
	if err == nil && len(der) == 0 {
		return C.SSL_TLSEXT_ERR_NOACK
	}
	if err == nil {
		if len(der) > 0xffffff {
			err = errors.New("tls: OCSP staple exceeds wire size")
		} else {
			data := append([]byte(nil), der...)
			if C.set_ocsp(ssl, (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data))) != 1 {
				err = errors.New("tls: could not install OCSP staple")
			}
		}
	}
	if err != nil {
		cb.Err = err
		return C.SSL_TLSEXT_ERR_ALERT_FATAL
	}
	return C.SSL_TLSEXT_ERR_OK
}
