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
	NidEmailAddress           = 48
	NidSerialNumber           = 105
	NidSurname                = 100
	NidGivenName              = 99
	NidTitle                  = 62
	// NidBasicConstraints 为 BasicConstraints 扩展 NID。
	NidBasicConstraints = 87
	// 扩展 NID（来自 objects.h / obj_mac.h）。
	NidSubjectAltName         = 85
	NidKeyUsage               = 83
	NidExtKeyUsage            = 126
	NidSubjectKeyIdentifier   = 82
	NidAuthorityKeyIdentifier = 90
	NidUndef                  = 0
)

// GENERAL_NAME 类型常量（来自 x509v3.h 宏）。
const (
	GenOtherName  = 0
	GenEmail      = 1
	GenDNS        = 2
	GenDirName    = 4
	GenEdiParty   = 5
	GenURI        = 6
	GenIPAdd      = 7
	GenRegistered = 8
	GenX400       = 3
	GenOther      = -1
)

// OBJ_nid2sn 返回 NID 对应的短名（如 "CN"），未知返回空串。
func OBJ_nid2sn(nid int) string {
	c := C.OBJ_nid2sn(C.int(nid))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// OBJ_obj2nid 返回 OID 对象对应的 NID（NidUndef 表示未知）。
func OBJ_obj2nid(o unsafe.Pointer) int {
	return int(C.OBJ_obj2nid((*C.ASN1_OBJECT)(o)))
}

// OBJ_txt2nid 按短名/长名/OID 文本解析 NID（NidUndef 表示未知）。
func OBJ_txt2nid(s string) int {
	c := C.CString(s)
	defer C.free(unsafe.Pointer(c))
	return int(C.OBJ_txt2nid(c))
}

// X509_NAME_get_entry_count 返回名字条目数。
func X509_NAME_get_entry_count(n unsafe.Pointer) int {
	return int(C.X_X509_NAME_entry_count((*C.X509_NAME)(n)))
}

// X509_NAME_get_entry 返回第 i 个名字条目（内部指针，勿释放）。
func X509_NAME_get_entry(n unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_NAME_get_entry((*C.X509_NAME)(n), C.int(i)))
}

// X509_NAME_ENTRY_nid 返回名字条目的 NID（NidUndef 表示未知）。
func X509_NAME_ENTRY_nid(e unsafe.Pointer) int {
	return int(C.X_X509_NAME_ENTRY_nid(e))
}

// X509_NAME_ENTRY_value 返回名字条目的 UTF-8 值。
func X509_NAME_ENTRY_value(e unsafe.Pointer) (string, bool) {
	c := C.X_X509_NAME_ENTRY_value(e)
	if c == nil {
		return "", false
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c), true
}

// X509_NAME_oneline 返回名字的单行文本（如 "/CN=.."）。
func X509_NAME_oneline(n unsafe.Pointer) (string, bool) {
	c := C.X_X509_NAME_oneline((*C.X509_NAME)(n))
	if c == nil {
		return "", false
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c), true
}

// X509_NAME_get_text_by_txt 按字段短名（如 "CN"、"O"）读取名字文本。
// 注意：X509_NAME_get_text_by_txt 在 OpenSSL 3.x 中为宏，故用 OBJ_txt2nid 组合实现。
func X509_NAME_get_text_by_txt(n unsafe.Pointer, field string) string {
	nid := OBJ_txt2nid(field)
	if nid == NidUndef {
		return ""
	}
	return X509_NAME_get_text_by_NID(n, nid)
}

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

// X509V3_EXT_conf_nid_ctx 带 X509V3_CTX 创建并追加扩展（SKID/AKID 需要 ctx）。
// subject/issuer 可传 nil（分别用于 SKID 的 subject 公钥、AKID 的 issuer 证书）。
func X509V3_EXT_conf_nid_ctx(target, subject, issuer unsafe.Pointer, nid int, value string) bool {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	return C.X_X509V3_EXT_conf_nid_ctx((*C.X509)(target),
		(*C.X509)(subject), (*C.X509)(issuer), C.int(nid), cVal) == 1
}

// X509_get_version 返回证书版本（0=v1，1=v2，2=v3）。
func X509_get_version(x unsafe.Pointer) int {
	return int(C.X509_get_version((*C.X509)(x)))
}

// X509_get_ext_count 返回证书扩展数量。
func X509_get_ext_count(x unsafe.Pointer) int {
	return int(C.X509_get_ext_count((*C.X509)(x)))
}

// X509_get_ext 返回第 i 个扩展（内部指针，勿释放）。
func X509_get_ext(x unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_ext((*C.X509)(x), C.int(i)))
}

// X509_EXTENSION_get_object 返回扩展 OID（内部指针）。
func X509_EXTENSION_get_object(e unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_EXTENSION_get_object((*C.X509_EXTENSION)(e)))
}

// X509_EXTENSION_get_critical 返回扩展 critical 标志。
func X509_EXTENSION_get_critical(e unsafe.Pointer) int {
	return int(C.X509_EXTENSION_get_critical((*C.X509_EXTENSION)(e)))
}

// X509_EXTENSION_get_data 返回扩展数据的 ASN1_OCTET_STRING（内部指针）。
func X509_EXTENSION_get_data(e unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_EXTENSION_get_data((*C.X509_EXTENSION)(e)))
}

// ASN1_STRING_data_bytes 返回 ASN1_STRING 的原始字节（复制）。
func ASN1_STRING_data_bytes(s unsafe.Pointer) []byte {
	length := C.ASN1_STRING_length((*C.ASN1_STRING)(s))
	data := C.ASN1_STRING_get0_data((*C.ASN1_STRING)(s))
	if length <= 0 || data == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(length))
}

// X509_digest 计算证书指纹。md 为摘要算法描述符。
func X509_digest(x, md unsafe.Pointer) ([]byte, bool) {
	var buf [64]C.uchar
	var n C.uint
	if C.X509_digest((*C.X509)(x), (*C.EVP_MD)(md), &buf[0], &n) != 1 {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), C.int(n)), true
}

// I2d_X509 将证书编码为 DER。
func I2d_X509(x unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_X509((*C.X509)(x), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_X509((*C.X509)(x), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// D2i_X509 从 DER 解析证书。
// 注意：der 须先复制到 C 内存，避免 cgo「Go 指针指向 Go 指针」规则违规。
func D2i_X509(der []byte) unsafe.Pointer {
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
	return unsafe.Pointer(C.d2i_X509(nil, &p, C.long(len(der))))
}

// I2d_X509_REQ 将 CSR 编码为 DER。
func I2d_X509_REQ(r unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_X509_REQ((*C.X509_REQ)(r), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_X509_REQ((*C.X509_REQ)(r), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// D2i_X509_REQ 从 DER 解析 CSR。
// 注意：der 须先复制到 C 内存，避免 cgo「Go 指针指向 Go 指针」规则违规。
func D2i_X509_REQ(der []byte) unsafe.Pointer {
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
	return unsafe.Pointer(C.d2i_X509_REQ(nil, &p, C.long(len(der))))
}

// X509_get_san 返回 SAN 扩展的 GENERAL_NAMES 栈（无则 nil）。调用方负责 X509_GENERAL_NAMES_free。
func X509_get_san(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_san((*C.X509)(x)))
}

// X509_GENERAL_NAMES_free 释放 GENERAL_NAMES 栈。
func X509_GENERAL_NAMES_free(sk unsafe.Pointer) {
	C.X_GENERAL_NAMES_free(sk)
}

// X509_GENERAL_NAMES_num 返回 SAN 条目数。
func X509_GENERAL_NAMES_num(sk unsafe.Pointer) int {
	return int(C.X_GENERAL_NAMES_num(sk))
}

// X509_GENERAL_NAMES_value 返回第 i 个 GENERAL_NAME（内部指针）。
func X509_GENERAL_NAMES_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_GENERAL_NAMES_value(sk, C.int(i)))
}

// X509_GENERAL_NAME_type 返回 GENERAL_NAME 类型（Gen* 常量）。
func X509_GENERAL_NAME_type(gn unsafe.Pointer) int {
	return int(C.X_GENERAL_NAME_type(gn))
}

// X509_GENERAL_NAME_to_string 返回 GENERAL_NAME 的值文本（如 "example.com"）。
func X509_GENERAL_NAME_to_string(gn unsafe.Pointer) string {
	c := C.X_GENERAL_NAME_to_string(gn)
	if c == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c)
}

// X509_get_key_usage 返回 KeyUsage 扩展的 ASN1_BIT_STRING（无则 nil）。调用方负责 X509_ASN1_BIT_STRING_free。
func X509_get_key_usage(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_key_usage((*C.X509)(x)))
}

// X509_ASN1_BIT_STRING_free 释放 ASN1_BIT_STRING。
func X509_ASN1_BIT_STRING_free(bs unsafe.Pointer) {
	C.X_ASN1_BIT_STRING_free(bs)
}

// ASN1_BIT_STRING_get_bit 读取位串第 bit 位。
func ASN1_BIT_STRING_get_bit(bs unsafe.Pointer, bit int) bool {
	return C.ASN1_BIT_STRING_get_bit((*C.ASN1_BIT_STRING)(bs), C.int(bit)) == 1
}

// X509_get_eku 返回 EKU 扩展的 EXTENDED_KEY_USAGE 栈（无则 nil）。调用方负责 X509_EXTENDED_KEY_USAGE_free。
func X509_get_eku(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_eku((*C.X509)(x)))
}

// X509_EXTENDED_KEY_USAGE_free 释放 EKU 栈。
func X509_EXTENDED_KEY_USAGE_free(sk unsafe.Pointer) {
	C.X_EXTENDED_KEY_USAGE_free(sk)
}

// X509_EXTENDED_KEY_USAGE_num 返回 EKU 条目数。
func X509_EXTENDED_KEY_USAGE_num(sk unsafe.Pointer) int {
	return int(C.X_EXTENDED_KEY_USAGE_num(sk))
}

// X509_EXTENDED_KEY_USAGE_value 返回第 i 个 EKU 的 ASN1_OBJECT（内部指针）。
func X509_EXTENDED_KEY_USAGE_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_EXTENDED_KEY_USAGE_value(sk, C.int(i)))
}

// OBJ_to_string 返回 ASN1_OBJECT 的名称或 OID 文本。
func OBJ_to_string(o unsafe.Pointer) string {
	c := C.X_OBJ_to_string(o)
	if c == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c)
}

// X509_get_basic_constraints 返回 BasicConstraints 扩展（无则 nil）。调用方负责 X509_BASIC_CONSTRAINTS_free。
func X509_get_basic_constraints(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_basic_constraints((*C.X509)(x)))
}

// X509_BASIC_CONSTRAINTS_free 释放 BASIC_CONSTRAINTS。
func X509_BASIC_CONSTRAINTS_free(bc unsafe.Pointer) {
	C.X_BASIC_CONSTRAINTS_free(bc)
}

// X509_BASIC_CONSTRAINTS_ca 返回 BasicConstraints 的 CA 标志。
func X509_BASIC_CONSTRAINTS_ca(bc unsafe.Pointer) int {
	return int(C.X_BASIC_CONSTRAINTS_ca(bc))
}

// X509_BASIC_CONSTRAINTS_pathlen 返回 pathlen（无约束为 -1）。
func X509_BASIC_CONSTRAINTS_pathlen(bc unsafe.Pointer) int64 {
	return int64(C.X_BASIC_CONSTRAINTS_pathlen(bc))
}

// X509_get0_subject_key_id 返回 SKID 字节（内部指针，勿释放）。
func X509_get0_subject_key_id(x unsafe.Pointer) []byte {
	c := C.X509_get0_subject_key_id((*C.X509)(x))
	if c == nil {
		return nil
	}
	return ASN1_STRING_data_bytes(unsafe.Pointer(c))
}

// X509_get0_authority_key_id 返回 AKID 中 keyid 字节（内部指针，勿释放）。
func X509_get0_authority_key_id(x unsafe.Pointer) []byte {
	c := C.X509_get0_authority_key_id((*C.X509)(x))
	if c == nil {
		return nil
	}
	return ASN1_STRING_data_bytes(unsafe.Pointer(c))
}

// X509_sk_X509_EXTENSION_new_null 创建空的扩展栈。
func X509_sk_X509_EXTENSION_new_null() unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_EXTENSION_new_null())
}

// X509_sk_X509_EXTENSION_push 向扩展栈压入扩展（栈不拥有该扩展）。
func X509_sk_X509_EXTENSION_push(sk, ext unsafe.Pointer) bool {
	return C.X_sk_X509_EXTENSION_push(sk, ext) == 1
}

// X509_sk_X509_EXTENSION_free 释放扩展栈（不释放元素）。
func X509_sk_X509_EXTENSION_free(sk unsafe.Pointer) {
	C.X_sk_X509_EXTENSION_free(sk)
}

// X509_sk_X509_EXTENSION_pop_free 释放扩展栈并释放全部元素。
func X509_sk_X509_EXTENSION_pop_free(sk unsafe.Pointer) {
	C.X_sk_X509_EXTENSION_pop_free(sk)
}

// X509_sk_X509_EXTENSION_num 返回扩展栈条目数。
func X509_sk_X509_EXTENSION_num(sk unsafe.Pointer) int {
	return int(C.X_sk_X509_EXTENSION_num(sk))
}

// X509_sk_X509_EXTENSION_value 返回扩展栈第 i 个扩展（内部指针）。
func X509_sk_X509_EXTENSION_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_EXTENSION_value(sk, C.int(i)))
}

// X509_REQ_add_extensions 为 CSR 添加扩展（须在 Sign 之前调用）。
func X509_REQ_add_extensions(r, sk unsafe.Pointer) bool {
	return C.X_X509_REQ_add_extensions((*C.X509_REQ)(r), sk) == 1
}

// X509_REQ_get_extensions 返回 CSR 中的扩展栈（调用方负责 X509_sk_X509_EXTENSION_pop_free）。
func X509_REQ_get_extensions(r unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_REQ_get_extensions((*C.X509_REQ)(r)))
}

// X509_REQ_set_challenge_password 设置 CSR 挑战密码（PKCS#9 challengePassword 属性）。
func X509_REQ_set_challenge_password(r unsafe.Pointer, pwd string) bool {
	c := C.CString(pwd)
	defer C.free(unsafe.Pointer(c))
	return C.X_X509_REQ_set_challenge_password((*C.X509_REQ)(r), c) == 1
}

// X509_REQ_get_challenge_password 返回 CSR 挑战密码（无则为空串）。
func X509_REQ_get_challenge_password(r unsafe.Pointer) string {
	c := C.X_X509_REQ_get_challenge_password((*C.X509_REQ)(r))
	if c == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c)
}

// NidCrlReason 为 CRL 吊销原因扩展 NID（来自 obj_mac.h）。
const NidCrlReason = 141

// X509_V_ERR_* 证书链验证错误码（来自 x509_vfy.h 宏）。
const (
	X509VOK                       = 0
	X509VErrUnableToGetIssuer     = 2
	X509VErrUnableToGetCRL        = 3
	X509VErrCertSignatureFail     = 7
	X509VErrCertNotYetValid       = 9
	X509VErrCertHasExpired        = 10
	X509VErrCRLNotYetValid        = 11
	X509VErrCRLHasExpired         = 12
	X509VErrDepthZeroSelfSigned   = 18
	X509VErrSelfSignedInChain     = 19
	X509VErrUnableToGetLocalIssue = 20
	X509VErrCertRevoked           = 23
)

// X509_V_FLAG_* 证书链验证标志（来自 x509_vfy.h 宏）。
const (
	X509VFlagCRLCheck    = 0x4
	X509VFlagCRLCheckAll = 0x8
)

// X509_dup 复制证书（返回新引用，调用方负责 X509_free）。
func X509_dup(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_dup((*C.X509)(x)))
}

// X509_STORE_new 创建证书存储。
func X509_STORE_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_new())
}

// X509_STORE_free 释放证书存储。
func X509_STORE_free(s unsafe.Pointer) {
	C.X509_STORE_free((*C.X509_STORE)(s))
}

// X509_STORE_add_cert 向存储添加信任证书（存储内部持引用，调用方仍拥有证书）。
func X509_STORE_add_cert(s, x unsafe.Pointer) bool {
	return C.X509_STORE_add_cert((*C.X509_STORE)(s), (*C.X509)(x)) == 1
}

// X509_STORE_add_crl 向存储添加 CRL（存储内部持引用）。
func X509_STORE_add_crl(s, crl unsafe.Pointer) bool {
	return C.X509_STORE_add_crl((*C.X509_STORE)(s), (*C.X509_CRL)(crl)) == 1
}

// X509_STORE_set_flags 设置存储验证标志。
func X509_STORE_set_flags(s unsafe.Pointer, flags uint64) bool {
	return C.X509_STORE_set_flags((*C.X509_STORE)(s), C.ulong(flags)) == 1
}

// X509_STORE_CTX_new 创建验证上下文。
func X509_STORE_CTX_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_CTX_new())
}

// X509_STORE_CTX_free 释放验证上下文。
func X509_STORE_CTX_free(ctx unsafe.Pointer) {
	C.X509_STORE_CTX_free((*C.X509_STORE_CTX)(ctx))
}

// X509_STORE_CTX_init 初始化验证上下文（store 为信任存储，cert 为待验证证书）。
func X509_STORE_CTX_init(ctx, store, cert unsafe.Pointer) bool {
	return C.X509_STORE_CTX_init((*C.X509_STORE_CTX)(ctx),
		(*C.X509_STORE)(store), (*C.X509)(cert), nil) == 1
}

// X509_STORE_CTX_set0_untrusted 设置中间证书链（所有权转移给 ctx，勿再释放）。
func X509_STORE_CTX_set0_untrusted(ctx, sk unsafe.Pointer) {
	C.X_X509_STORE_CTX_set0_untrusted((*C.X509_STORE_CTX)(ctx), sk)
}

// X509_verify_cert 验证证书链（1=通过，0=失败，-1=内部错误）。
func X509_verify_cert(ctx unsafe.Pointer) int {
	return int(C.X509_verify_cert((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get_error 返回验证错误码。
func X509_STORE_CTX_get_error(ctx unsafe.Pointer) int {
	return int(C.X509_STORE_CTX_get_error((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get_error_depth 返回出错深度。
func X509_STORE_CTX_get_error_depth(ctx unsafe.Pointer) int {
	return int(C.X509_STORE_CTX_get_error_depth((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get_current_cert 返回出错证书（内部指针，勿释放）。
func X509_STORE_CTX_get_current_cert(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_CTX_get_current_cert((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get0_chain 返回已验证链（内部栈，勿释放）。
func X509_STORE_CTX_get0_chain(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_CTX_get0_chain((*C.X509_STORE_CTX)(ctx)))
}

// X509_verify_cert_error_string 返回验证错误码对应的描述。
func X509_verify_cert_error_string(code int) string {
	c := C.X509_verify_cert_error_string(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// X509_sk_X509_new_null 创建 X509 栈。
func X509_sk_X509_new_null() unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_new_null())
}

// X509_sk_X509_push 向 X509 栈压入证书（栈不拥有元素）。
func X509_sk_X509_push(sk, x unsafe.Pointer) bool {
	return C.X_sk_X509_push(sk, x) == 1
}

// X509_sk_X509_free 释放 X509 栈（不释放元素）。
func X509_sk_X509_free(sk unsafe.Pointer) {
	C.X_sk_X509_free(sk)
}

// X509_sk_X509_pop_free 释放 X509 栈并释放全部元素。
func X509_sk_X509_pop_free(sk unsafe.Pointer) {
	C.X_sk_X509_pop_free(sk)
}

// X509_sk_X509_num 返回 X509 栈条目数。
func X509_sk_X509_num(sk unsafe.Pointer) int {
	return int(C.X_sk_X509_num(sk))
}

// X509_sk_X509_value 返回 X509 栈第 i 个证书（内部指针）。
func X509_sk_X509_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_value(sk, C.int(i)))
}

// X509_NAME_cmp 比较两个名字（0=相等）。
func X509_NAME_cmp(a, b unsafe.Pointer) int {
	return int(C.X509_NAME_cmp((*C.X509_NAME)(a), (*C.X509_NAME)(b)))
}

// D2i_X509_CRL 从 DER 解析 CRL。
func D2i_X509_CRL(der []byte) unsafe.Pointer {
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
	return unsafe.Pointer(C.d2i_X509_CRL(nil, &p, C.long(len(der))))
}

// I2d_X509_CRL 将 CRL 编码为 DER。
func I2d_X509_CRL(crl unsafe.Pointer) ([]byte, bool) {
	n := C.i2d_X509_CRL((*C.X509_CRL)(crl), nil)
	if n <= 0 {
		return nil, false
	}
	buf := C.malloc(C.size_t(n))
	if buf == nil {
		return nil, false
	}
	defer C.free(buf)
	p := (*C.uchar)(buf)
	C.i2d_X509_CRL((*C.X509_CRL)(crl), &p)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), true
}

// X_PEM_read_bio_X509_CRL 从 BIO 读取 PEM CRL。
func X_PEM_read_bio_X509_CRL(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_X509_CRL((*C.BIO)(bio)))
}

// X_PEM_write_bio_X509_CRL 将 CRL 以 PEM 写入 BIO。
func X_PEM_write_bio_X509_CRL(bio unsafe.Pointer, crl unsafe.Pointer) bool {
	return C.X_PEM_write_bio_X509_CRL((*C.BIO)(bio), (*C.X509_CRL)(crl)) == 1
}

// X509_CRL_free 释放 CRL。
func X509_CRL_free(crl unsafe.Pointer) {
	C.X509_CRL_free((*C.X509_CRL)(crl))
}

// X509_CRL_get_version 返回 CRL 版本。
func X509_CRL_get_version(crl unsafe.Pointer) int {
	return int(C.X509_CRL_get_version((*C.X509_CRL)(crl)))
}

// X509_CRL_get0_lastUpdate 返回 CRL 生效时间（unix 秒）。
func X509_CRL_get0_lastUpdate(crl unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_CRL_get0_lastUpdate((*C.X509_CRL)(crl)))
}

// X509_CRL_get0_nextUpdate 返回 CRL 过期时间（unix 秒）。
func X509_CRL_get0_nextUpdate(crl unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_CRL_get0_nextUpdate((*C.X509_CRL)(crl)))
}

// X509_CRL_get_issuer 返回 CRL 签发者名字（内部指针，勿释放）。
func X509_CRL_get_issuer(crl unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_get_issuer((*C.X509_CRL)(crl)))
}

// X509_CRL_get_REVOKED 返回 CRL 吊销条目栈（内部指针，勿释放）。
func X509_CRL_get_REVOKED(crl unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_get_REVOKED((*C.X509_CRL)(crl)))
}

// X509_sk_X509_REVOKED_num 返回吊销条目数。
func X509_sk_X509_REVOKED_num(sk unsafe.Pointer) int {
	return int(C.X_sk_X509_REVOKED_num(sk))
}

// X509_sk_X509_REVOKED_value 返回第 i 个吊销条目（内部指针）。
func X509_sk_X509_REVOKED_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_REVOKED_value(sk, C.int(i)))
}

// X509_REVOKED_get0_serialNumber 返回吊销条目的序列号。
func X509_REVOKED_get0_serialNumber(rev unsafe.Pointer) int64 {
	ai := C.X509_REVOKED_get0_serialNumber((*C.X509_REVOKED)(rev))
	if ai == nil {
		return 0
	}
	return int64(C.ASN1_INTEGER_get(ai))
}

// X509_REVOKED_get0_revocationDate 返回吊销条目的吊销时间（unix 秒）。
func X509_REVOKED_get0_revocationDate(rev unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_REVOKED_get0_revocationDate((*C.X509_REVOKED)(rev)))
}

// X509_REVOKED_crl_reason 返回吊销条目的原因码（无原因返回 -1）。
func X509_REVOKED_crl_reason(rev unsafe.Pointer) int {
	en := C.X509_REVOKED_get_ext_d2i((*C.X509_REVOKED)(rev), C.int(NidCrlReason), nil, nil)
	if en == nil {
		return -1
	}
	defer C.X_ASN1_ENUMERATED_free(en)
	return int(C.ASN1_ENUMERATED_get((*C.ASN1_ENUMERATED)(en)))
}
