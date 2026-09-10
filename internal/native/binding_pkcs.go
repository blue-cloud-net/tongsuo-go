package native

/*
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include "shim.h"
*/
import "C"
import "unsafe"

// PKCS#7 SignedData 类型常量（来自 obj_mac.h）。
//
// NidPKCS7Signed is the PKCS#7 NID (22) for SignedData; pass it to
// PKCS7_set_type when constructing a signed PKCS#7 container.
const NidPKCS7Signed = 22

// X_PKCS12_create 打包证书、私钥与 CA 链为 PKCS12。
// ca 为借用证书指针数组（长度与 ca 相同）。
// X_PKCS12_create (X_PKCS12_create shim) bundles pkey, cert, and an optional
// CA chain into a PKCS#12 PFX. ca is a borrowed slice of X509 pointers and
// must have the same length as the underlying array. The caller owns the
// returned PKCS12 and must release it with PKCS12_free.
func X_PKCS12_create(pass, name string, pkey, cert unsafe.Pointer, ca []unsafe.Pointer) unsafe.Pointer {
	cPass := C.CString(pass)
	defer C.free(unsafe.Pointer(cPass))
	var cName *C.char
	if name != "" {
		cName = C.CString(name)
		defer C.free(unsafe.Pointer(cName))
	}
	var caPtr unsafe.Pointer
	if len(ca) > 0 {
		size := C.size_t(len(ca)) * C.size_t(unsafe.Sizeof((*C.X509)(nil)))
		buf := C.malloc(size)
		if buf == nil {
			return nil
		}
		defer C.free(buf)
		arr := (*[1 << 28]*C.X509)(buf)
		for i, x := range ca {
			arr[i] = (*C.X509)(x)
		}
		caPtr = buf
	}
	return unsafe.Pointer(C.X_PKCS12_create(cPass, cName, (*C.EVP_PKEY)(pkey),
		(*C.X509)(cert), (*unsafe.Pointer)(caPtr), C.int(len(ca))))
}

// X_PKCS12_parse 解析 PKCS12，返回私钥、主证书与 CA 栈。
// ca 栈归调用方所有，须用 X509_sk_X509_EXTENSION_pop_free 类似方式释放（sk_X509_pop_free）。
// X_PKCS12_parse (X_PKCS12_parse shim) decrypts p12 with pass and returns
// (pkey, cert, ca, ok). The returned pkey and cert are new references that
// the caller must release with EVP_PKEY_free / X509_free; ca is an X509
// stack that must be released with X509_sk_X509_pop_free.
func X_PKCS12_parse(p12 unsafe.Pointer, pass string) (pkey, cert, ca unsafe.Pointer, ok bool) {
	cPass := C.CString(pass)
	defer C.free(unsafe.Pointer(cPass))
	var cKey *C.EVP_PKEY
	var cCert *C.X509
	var cCa unsafe.Pointer
	ok = C.X_PKCS12_parse((*C.PKCS12)(p12), cPass, &cKey, &cCert, &cCa) == 1
	return unsafe.Pointer(cKey), unsafe.Pointer(cCert), cCa, ok
}

// PKCS12_free 释放 PKCS12。
// PKCS12_free releases the PKCS12. Safe on NULL; the pointer must not be
// used after free.
func PKCS12_free(p12 unsafe.Pointer) {
	C.PKCS12_free((*C.PKCS12)(p12))
}

// I2d_PKCS12 将 PKCS12 编码为 DER。
// I2d_PKCS12 serializes p12 to DER. Returns (bytes, true) on success or
// (nil, false) when the encoder reports a non-positive length.
func I2d_PKCS12(p12 unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_PKCS12((*C.PKCS12)(p12), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_PKCS12((*C.PKCS12)(p12), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// D2i_PKCS12 从 DER 解析 PKCS12。
// D2i_PKCS12 parses a PKCS12 PFX from the given DER bytes. Returns NULL on
// empty input or parse failure. The caller owns the result and must free
// it with PKCS12_free.
func D2i_PKCS12(der []byte) unsafe.Pointer {
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
	return unsafe.Pointer(C.d2i_PKCS12(nil, &p, C.long(len(der))))
}

// PKCS12_newpass 修改 PKCS12 口令。
// PKCS12_newpass re-encrypts p12 from oldPass to newPass. Returns true on
// success; the original integrity MAC is replaced.
func PKCS12_newpass(p12 unsafe.Pointer, oldPass, newPass string) bool {
	cOld := C.CString(oldPass)
	defer C.free(unsafe.Pointer(cOld))
	cNew := C.CString(newPass)
	defer C.free(unsafe.Pointer(cNew))
	return C.PKCS12_newpass((*C.PKCS12)(p12), cOld, cNew) == 1
}

// PKCS12_set_mac 为 PKCS12 重新计算 MAC（SHA-256，iter=2048）。
// PKCS12_set_mac recomputes the integrity MAC on p12 using SHA-256 with
// 2048 PBKDF2 iterations. Returns true on success.
func PKCS12_set_mac(p12 unsafe.Pointer, pass string) bool {
	cPass := C.CString(pass)
	defer C.free(unsafe.Pointer(cPass))
	return C.PKCS12_set_mac((*C.PKCS12)(p12), cPass, C.int(len(pass)),
		nil, 0, 2048, C.EVP_sha256()) == 1
}

// PKCS7_new 创建空的 PKCS7。
// PKCS7_new allocates and returns an empty PKCS7. The caller owns the
// returned pointer and must release it with PKCS7_free.
func PKCS7_new() unsafe.Pointer {
	return unsafe.Pointer(C.PKCS7_new())
}

// PKCS7_free 释放 PKCS7。
// PKCS7_free releases the PKCS7. Safe on NULL; the pointer must not be used
// after free.
func PKCS7_free(p7 unsafe.Pointer) {
	C.PKCS7_free((*C.PKCS7)(p7))
}

// PKCS7_set_type 设置 PKCS7 类型（如 NidPKCS7Signed）。
// PKCS7_set_type sets the type of p7 (e.g. NidPKCS7Signed). Returns true on
// success.
func PKCS7_set_type(p7 unsafe.Pointer, typ int) bool {
	return C.PKCS7_set_type((*C.PKCS7)(p7), C.int(typ)) == 1
}

// PKCS7_content_new 设置 SignedData 的 content 类型（如 NID_pkcs7_data）。
// PKCS7_content_new assigns the inner content type (typically NID_pkcs7_data)
// inside a SignedData PKCS7. Returns true on success.
func PKCS7_content_new(p7 unsafe.Pointer, nid int) bool {
	return C.PKCS7_content_new((*C.PKCS7)(p7), C.int(nid)) == 1
}

// PKCS7_add_certificate 向 SignedData 追加证书（内部复制）。
// PKCS7_add_certificate copies cert into the SignedData container; the caller
// retains ownership of cert.
func PKCS7_add_certificate(p7, cert unsafe.Pointer) bool {
	return C.PKCS7_add_certificate((*C.PKCS7)(p7), (*C.X509)(cert)) == 1
}

// PKCS7_get0_certificates 返回 SignedData 的证书栈（内部指针，勿释放）。
// PKCS7_get0_certificates returns the internal cert stack of a SignedData
// PKCS7. The pointer is owned by p7 and must NOT be freed.
func PKCS7_get0_certificates(p7 unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PKCS7_get0_certificates((*C.PKCS7)(p7)))
}

// I2d_PKCS7 将 PKCS7 编码为 DER。
// I2d_PKCS7 serializes p7 to DER. Returns (bytes, true) on success or
// (nil, false) when the encoder reports a non-positive length.
func I2d_PKCS7(p7 unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_PKCS7((*C.PKCS7)(p7), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_PKCS7((*C.PKCS7)(p7), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// D2i_PKCS7 从 DER 解析 PKCS7。
// D2i_PKCS7 parses a PKCS7 structure from the given DER bytes. Returns NULL
// on empty input or parse failure. The caller owns the result and must free
// it with PKCS7_free.
func D2i_PKCS7(der []byte) unsafe.Pointer {
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
	return unsafe.Pointer(C.d2i_PKCS7(nil, &p, C.long(len(der))))
}
