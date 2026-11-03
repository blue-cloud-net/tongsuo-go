package native

/*
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// X_X509_add_trust 添加信任或拒绝用途；对象按名称或点分 OID 解析。
//
// X_X509_add_trust adds a trusted/rejected purpose identified by name or dotted OID.
func X_X509_add_trust(cert unsafe.Pointer, purpose string, reject bool) bool {
	name := C.CString(purpose)
	defer C.free(unsafe.Pointer(name))
	obj := C.OBJ_txt2obj(name, 0)
	if obj == nil {
		return false
	}
	defer C.ASN1_OBJECT_free(obj)
	if reject {
		return C.X509_add1_reject_object((*C.X509)(cert), obj) == 1
	}
	return C.X509_add1_trust_object((*C.X509)(cert), obj) == 1
}

// X_X509_clear_trust 清空信任或拒绝用途。
//
// X_X509_clear_trust clears trusted or rejected purposes.
func X_X509_clear_trust(cert unsafe.Pointer, reject bool) {
	if reject {
		C.X509_reject_clear((*C.X509)(cert))
	} else {
		C.X509_trust_clear((*C.X509)(cert))
	}
}

// PEM_write_bio_X509_AUX 编码包含信任属性的证书。
//
// PEM_write_bio_X509_AUX encodes a certificate with its trust attributes.
func PEM_write_bio_X509_AUX(bio, cert unsafe.Pointer) bool {
	return C.PEM_write_bio_X509_AUX((*C.BIO)(bio), (*C.X509)(cert)) == 1
}

// PEM_read_bio_X509_AUX 加载包含信任属性的证书，调用方拥有结果。
//
// PEM_read_bio_X509_AUX loads a certificate with trust attributes, returning an owned pointer.
func PEM_read_bio_X509_AUX(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.PEM_read_bio_X509_AUX((*C.BIO)(bio), nil, nil, nil))
}
