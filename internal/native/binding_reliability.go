package native

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// X_X509_set_serial_hex 无损写入证书序列号。
// X_X509_set_serial_hex writes a complete certificate serial number.
func X_X509_set_serial_hex(cert unsafe.Pointer, serial string) bool {
	s := C.CString(serial)
	defer C.free(unsafe.Pointer(s))
	return C.X_X509_set_serial_hex((*C.X509)(cert), s) == 1
}

// X_X509_REVOKED_set_serial_hex 无损写入吊销序列号。
// X_X509_REVOKED_set_serial_hex writes a complete revoked serial number.
func X_X509_REVOKED_set_serial_hex(rev unsafe.Pointer, serial string) bool {
	s := C.CString(serial)
	defer C.free(unsafe.Pointer(s))
	return C.X_X509_REVOKED_set_serial_hex((*C.X509_REVOKED)(rev), s) == 1
}

// X_X509_REVOKED_serial_hex 无损读取带符号吊销序列号。
// X_X509_REVOKED_serial_hex reads the complete signed revoked serial number.
func X_X509_REVOKED_serial_hex(rev unsafe.Pointer) string {
	s := C.X_X509_REVOKED_serial_hex((*C.X509_REVOKED)(rev))
	if s == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(s))
	return C.GoString(s)
}

// X_X509_add_ext_der 按点分 OID 添加原始扩展。
// X_X509_add_ext_der adds a raw extension using its numeric OID.
func X_X509_add_ext_der(cert unsafe.Pointer, oid string, critical bool, der []byte) bool {
	s := C.CString(oid)
	defer C.free(unsafe.Pointer(s))
	data := C.CBytes(der)
	defer C.free(data)
	flag := C.int(0)
	if critical {
		flag = 1
	}
	return C.X_X509_add_ext_der((*C.X509)(cert), s, flag, (*C.uchar)(data), C.int(len(der))) == 1
}

// X509_STORE_set_default_paths 加载铜锁默认信任路径。
// X509_STORE_set_default_paths loads the Tongsuo default trust paths.
func X509_STORE_set_default_paths(store unsafe.Pointer) bool {
	return C.X509_STORE_set_default_paths((*C.X509_STORE)(store)) == 1
}

// X509_STORE_load_locations 加载显式 CA 文件和目录。
// X509_STORE_load_locations loads an explicit CA file and directory.
func X509_STORE_load_locations(store unsafe.Pointer, file, dir string) bool {
	var f, d *C.char
	if file != "" {
		f = C.CString(file)
		defer C.free(unsafe.Pointer(f))
	}
	if dir != "" {
		d = C.CString(dir)
		defer C.free(unsafe.Pointer(d))
	}
	return C.X509_STORE_load_locations((*C.X509_STORE)(store), f, d) == 1
}

// X_SM2_expand_point 校验并展开压缩 SM2 点。
// X_SM2_expand_point validates and expands a compressed SM2 point.
func X_SM2_expand_point(in []byte) ([]byte, bool) {
	if len(in) != 33 {
		return nil, false
	}
	data := C.CBytes(in)
	defer C.free(data)
	out := C.malloc(65)
	if out == nil {
		return nil, false
	}
	defer C.free(out)
	if C.X_SM2_expand_point((*C.uchar)(data), C.size_t(len(in)), (*C.uchar)(out)) != 1 {
		return nil, false
	}
	return C.GoBytes(out, 65), true
}

// X_PKCS12_reencrypt 无损重加密复杂 safe/bag，失败返回 nil。
// X_PKCS12_reencrypt losslessly reencrypts complex safes/bags, returning nil on failure.
func X_PKCS12_reencrypt(input unsafe.Pointer, oldPass, newPass, pbe string, iter int, name string) unsafe.Pointer {
	old := C.CString(oldPass)
	defer C.free(unsafe.Pointer(old))
	next := C.CString(newPass)
	defer C.free(unsafe.Pointer(next))
	alg := C.CString(pbe)
	defer C.free(unsafe.Pointer(alg))
	label := C.CString(name)
	defer C.free(unsafe.Pointer(label))
	return unsafe.Pointer(C.X_PKCS12_reencrypt((*C.PKCS12)(input), old, next, alg, C.int(iter), label))
}
