package native

/*
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include "shim.h"
*/
import "C"
import (
	"time"
	"unsafe"
)

// X509_NAME 相关 NID 常量（来自 objects.h 宏）。
const (
	NidCommonName             = 13
	NidCountryName            = 14
	NidLocalityName           = 15
	NidStateOrProvinceName    = 16
	NidOrganizationName       = 17
	NidOrganizationalUnitName = 18
	NidSerialNumber           = 105
	NidEmailAddress           = 48
	// NidBasicConstraints 为 BasicConstraints 扩展 NID。
	NidBasicConstraints = 87
)

// X509_NAME_new 创建新的 X509_NAME。
func X509_NAME_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_NAME_new())
}

// X509_NAME_free 释放 X509_NAME。
func X509_NAME_free(n unsafe.Pointer) {
	C.X509_NAME_free((*C.X509_NAME)(n))
}

// X509_NAME_add_entry_by_txt 添加名字条目（field 如 "CN"、"C"、"O"）。
func X509_NAME_add_entry_by_txt(n unsafe.Pointer, field, value string) bool {
	cField := C.CString(field)
	defer C.free(unsafe.Pointer(cField))
	// MBSTRING_ASC = 0x1001（MBSTRING_FLAG|1）。
	b := []byte(value)
	if len(b) == 0 {
		return C.X509_NAME_add_entry_by_txt((*C.X509_NAME)(n), cField,
			C.int(0x1001), nil, 0, 0, 0) == 1
	}
	return C.X509_NAME_add_entry_by_txt((*C.X509_NAME)(n), cField,
		C.int(0x1001), (*C.uchar)(unsafe.Pointer(&b[0])), C.int(len(b)), 0, 0) == 1
}

// X509_NAME_get_text_by_NID 按 NID 读取名字文本。
func X509_NAME_get_text_by_NID(n unsafe.Pointer, nid int) string {
	var buf [256]C.char
	nlen := C.X509_NAME_get_text_by_NID((*C.X509_NAME)(n), C.int(nid),
		&buf[0], C.int(len(buf)))
	if nlen < 0 {
		return ""
	}
	return C.GoString(&buf[0])
}

// X509_new 创建新的证书对象。
func X509_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_new())
}

// X509_free 释放证书对象。
func X509_free(x unsafe.Pointer) {
	C.X509_free((*C.X509)(x))
}

// X509_set_version 设置证书版本（0=v1，2=v3）。
func X509_set_version(x unsafe.Pointer, version int) bool {
	return C.X509_set_version((*C.X509)(x), C.long(version)) == 1
}

// X509_set_serial_int 设置证书序列号（整型）。
func X509_set_serial_int(x unsafe.Pointer, serial int64) bool {
	ai := C.ASN1_INTEGER_new()
	if ai == nil {
		return false
	}
	defer C.ASN1_INTEGER_free(ai)
	if C.ASN1_INTEGER_set(ai, C.long(serial)) != 1 {
		return false
	}
	return C.X509_set_serialNumber((*C.X509)(x), ai) == 1
}

// X509_get_serial_int 读取证书序列号（整型）。
func X509_get_serial_int(x unsafe.Pointer) int64 {
	ai := C.X509_get_serialNumber((*C.X509)(x))
	if ai == nil {
		return 0
	}
	return int64(C.ASN1_INTEGER_get(ai))
}

// X509_set_issuer_name 设置签发者名字。
func X509_set_issuer_name(x, n unsafe.Pointer) bool {
	return C.X509_set_issuer_name((*C.X509)(x), (*C.X509_NAME)(n)) == 1
}

// X509_set_subject_name 设置主题名字。
func X509_set_subject_name(x, n unsafe.Pointer) bool {
	return C.X509_set_subject_name((*C.X509)(x), (*C.X509_NAME)(n)) == 1
}

// X509_get_issuer_name 读取签发者名字（内部指针，勿释放）。
func X509_get_issuer_name(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_issuer_name((*C.X509)(x)))
}

// X509_get_subject_name 读取主题名字（内部指针，勿释放）。
func X509_get_subject_name(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_subject_name((*C.X509)(x)))
}

// X509_set_pubkey 设置证书公钥。
func X509_set_pubkey(x, pkey unsafe.Pointer) bool {
	return C.X509_set_pubkey((*C.X509)(x), (*C.EVP_PKEY)(pkey)) == 1
}

// X509_get_pubkey 读取证书公钥（返回新引用，调用方负责 EVP_PKEY_free）。
func X509_get_pubkey(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_pubkey((*C.X509)(x)))
}

// X509_set_not_before 设置生效时间（unix 秒）。
func X509_set_not_before(x unsafe.Pointer, t int64) bool {
	timePtr := C.X509_getm_notBefore((*C.X509)(x))
	return C.ASN1_TIME_set(timePtr, C.long(t)) != nil
}

// X509_set_not_after 设置过期时间（unix 秒）。
func X509_set_not_after(x unsafe.Pointer, t int64) bool {
	timePtr := C.X509_getm_notAfter((*C.X509)(x))
	return C.ASN1_TIME_set(timePtr, C.long(t)) != nil
}

// X509_get_not_before 读取生效时间（unix 秒）。
func X509_get_not_before(x unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_getm_notBefore((*C.X509)(x)))
}

// X509_get_not_after 读取过期时间（unix 秒）。
func X509_get_not_after(x unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_getm_notAfter((*C.X509)(x)))
}

func asn1TimeToUnix(s *C.ASN1_TIME) int64 {
	if s == nil {
		return 0
	}
	var tm C.struct_tm
	if C.ASN1_TIME_to_tm(s, &tm) != 1 {
		return 0
	}
	t := time.Date(int(tm.tm_year)+1900, time.Month(int(tm.tm_mon)+1), int(tm.tm_mday),
		int(tm.tm_hour), int(tm.tm_min), int(tm.tm_sec), 0, time.UTC)
	return t.Unix()
}

// X509_sign 使用签名密钥与摘要算法对证书签名。成功返回签名长度（非 0）。
func X509_sign(x, pkey, md unsafe.Pointer) bool {
	return C.X509_sign((*C.X509)(x), (*C.EVP_PKEY)(pkey), (*C.EVP_MD)(md)) != 0
}

// X509_verify 使用公钥验证证书签名。
func X509_verify(x, pkey unsafe.Pointer) bool {
	return C.X509_verify((*C.X509)(x), (*C.EVP_PKEY)(pkey)) == 1
}

// X509V3_EXT_conf_nid 按 NID 与配置值创建扩展对象（如 basicConstraints）。
func X509V3_EXT_conf_nid(nid int, value string) unsafe.Pointer {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	return unsafe.Pointer(C.X509V3_EXT_conf_nid(nil, nil, C.int(nid), cVal))
}

// X509_add_ext 向证书追加扩展。
func X509_add_ext(x, ext unsafe.Pointer) bool {
	return C.X509_add_ext((*C.X509)(x), (*C.X509_EXTENSION)(ext), C.int(-1)) == 1
}

// X509_EXTENSION_free 释放扩展对象。
func X509_EXTENSION_free(ext unsafe.Pointer) {
	C.X509_EXTENSION_free((*C.X509_EXTENSION)(ext))
}

// X_PEM_read_bio_X509 从 BIO 读取 PEM 证书。
func X_PEM_read_bio_X509(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_X509((*C.BIO)(bio)))
}

// X_PEM_write_bio_X509 将证书以 PEM 写入 BIO。
func X_PEM_write_bio_X509(bio unsafe.Pointer, x unsafe.Pointer) bool {
	return C.X_PEM_write_bio_X509((*C.BIO)(bio), (*C.X509)(x)) == 1
}

// X509_REQ_new 创建新的证书签名请求。
func X509_REQ_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_REQ_new())
}

// X509_REQ_free 释放证书签名请求。
func X509_REQ_free(r unsafe.Pointer) {
	C.X509_REQ_free((*C.X509_REQ)(r))
}

// X509_REQ_set_pubkey 设置 CSR 公钥。
func X509_REQ_set_pubkey(r, pkey unsafe.Pointer) bool {
	return C.X509_REQ_set_pubkey((*C.X509_REQ)(r), (*C.EVP_PKEY)(pkey)) == 1
}

// X509_REQ_set_subject_name 设置 CSR 主题。
func X509_REQ_set_subject_name(r, n unsafe.Pointer) bool {
	return C.X509_REQ_set_subject_name((*C.X509_REQ)(r), (*C.X509_NAME)(n)) == 1
}

// X509_REQ_sign 对 CSR 签名。成功返回签名长度（非 0）。
func X509_REQ_sign(r, pkey, md unsafe.Pointer) bool {
	return C.X509_REQ_sign((*C.X509_REQ)(r), (*C.EVP_PKEY)(pkey), (*C.EVP_MD)(md)) != 0
}

// X509_REQ_verify 验证 CSR 签名（使用其自身公钥）。
func X509_REQ_verify(r, pkey unsafe.Pointer) bool {
	return C.X509_REQ_verify((*C.X509_REQ)(r), (*C.EVP_PKEY)(pkey)) == 1
}

// X509_REQ_get_pubkey 读取 CSR 公钥（返回新引用）。
func X509_REQ_get_pubkey(r unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_REQ_get_pubkey((*C.X509_REQ)(r)))
}

// X509_REQ_get_subject_name 读取 CSR 主题（内部指针）。
func X509_REQ_get_subject_name(r unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_REQ_get_subject_name((*C.X509_REQ)(r)))
}

// I2d_X509_REQ_INFO 将 CSR 的 CertificationRequestInfo 编码为 DER（签名覆盖的数据）。
func I2d_X509_REQ_INFO(r unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_X509_REQ_INFO((*C.X509_REQ_INFO)(r), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_X509_REQ_INFO((*C.X509_REQ_INFO)(r), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// X509_REQ_get0_signature 返回 CSR 签名原始字节。
func X509_REQ_get0_signature(r unsafe.Pointer) ([]byte, bool) {
	var psig *C.ASN1_BIT_STRING
	var palg *C.X509_ALGOR
	C.X509_REQ_get0_signature((*C.X509_REQ)(r), &psig, &palg)
	if psig == nil {
		return nil, false
	}
	length := C.ASN1_STRING_length((*C.ASN1_STRING)(psig))
	data := C.ASN1_STRING_get0_data((*C.ASN1_STRING)(psig))
	if length <= 0 || data == nil {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(length)), true
}

// X_PEM_read_bio_X509_REQ 从 BIO 读取 PEM CSR。
func X_PEM_read_bio_X509_REQ(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_X509_REQ((*C.BIO)(bio)))
}

// X_PEM_write_bio_X509_REQ 将 CSR 以 PEM 写入 BIO。
func X_PEM_write_bio_X509_REQ(bio unsafe.Pointer, r unsafe.Pointer) bool {
	return C.X_PEM_write_bio_X509_REQ((*C.BIO)(bio), (*C.X509_REQ)(r)) == 1
}
