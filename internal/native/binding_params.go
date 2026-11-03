package native

/*
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// X_EC_parameters_write 写出命名或显式曲线参数。
//
// X_EC_parameters_write writes named or explicit EC parameters.
func X_EC_parameters_write(bio unsafe.Pointer, name string, explicit bool) bool {
	s := C.CString(name)
	defer C.free(unsafe.Pointer(s))
	nid := C.OBJ_txt2nid(s)
	if nid == 0 {
		return false
	}
	group := C.EC_GROUP_new_by_curve_name(nid)
	if group == nil {
		return false
	}
	defer C.EC_GROUP_free(group)
	flag := C.int(C.OPENSSL_EC_NAMED_CURVE)
	if explicit {
		flag = 0
	}
	C.EC_GROUP_set_asn1_flag(group, flag)
	return C.PEM_write_bio_ECPKParameters((*C.BIO)(bio), group) == 1
}

// X_EC_parameters_read 读取并校验曲线参数，返回曲线名。
//
// X_EC_parameters_read reads and validates EC parameters, returning the curve name.
func X_EC_parameters_read(bio unsafe.Pointer) string {
	group := C.PEM_read_bio_ECPKParameters((*C.BIO)(bio), nil, nil, nil)
	if group == nil {
		return ""
	}
	defer C.EC_GROUP_free(group)
	if C.EC_GROUP_check(group, nil) != 1 {
		return ""
	}
	nid := C.EC_GROUP_check_named_curve(group, 0, nil)
	if nid <= 0 {
		return ""
	}
	return C.GoString(C.OBJ_nid2sn(nid))
}

// X_EVP_PKEY_check 验证公钥或完整密钥对。
//
// X_EVP_PKEY_check validates a public key or a complete key pair.
func X_EVP_PKEY_check(key unsafe.Pointer, public bool) bool {
	ctx := C.EVP_PKEY_CTX_new_from_pkey(nil, (*C.EVP_PKEY)(key), nil)
	if ctx == nil {
		return false
	}
	defer C.EVP_PKEY_CTX_free(ctx)
	if public {
		return C.EVP_PKEY_public_check(ctx) == 1
	}
	return C.EVP_PKEY_check(ctx) == 1
}
