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
//
// NidCommonName through NidTitle are the X.500 Name NIDs (CN, C, L, ST, O,
// OU, emailAddress, serialNumber, Surname, GN, Title) used to build / read
// X509_NAME entries; NidBasicConstraints / NidSubjectAltName / NidKeyUsage /
// NidExtKeyUsage / NidSubjectKeyIdentifier / NidAuthorityKeyIdentifier are
// X.509 extension NIDs. NidUndef marks "unknown NID".
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
//
// Gen* are the GENERAL_NAME type tags returned by X509_GENERAL_NAME_type
// (GenOtherName, GenEmail, GenDNS, GenDirName, GenEdiParty, GenURI,
// GenIPAdd, GenRegistered, GenX400, GenOther).
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
//
// OBJ_nid2sn returns the short name (SN) for nid (e.g. "CN" for NidCommonName),
// or "" when the NID is unknown or the C string is NULL.
func OBJ_nid2sn(nid int) string {
	c := C.OBJ_nid2sn(C.int(nid))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// OBJ_obj2nid 返回 OID 对象对应的 NID（NidUndef 表示未知）。
//
// OBJ_obj2nid returns the NID for the ASN1_OBJECT o, or NidUndef when the
// OID is not recognized.
func OBJ_obj2nid(o unsafe.Pointer) int {
	return int(C.OBJ_obj2nid((*C.ASN1_OBJECT)(o)))
}

// OBJ_txt2nid 按短名/长名/OID 文本解析 NID（NidUndef 表示未知）。
//
// OBJ_txt2nid parses s as a short name, long name, or dotted OID and returns
// the matching NID, or NidUndef when nothing matches.
func OBJ_txt2nid(s string) int {
	c := C.CString(s)
	defer C.free(unsafe.Pointer(c))
	return int(C.OBJ_txt2nid(c))
}

// X509_NAME_get_entry_count 返回名字条目数。
//
// X509_NAME_get_entry_count returns the number of RDN entries in n.
func X509_NAME_get_entry_count(n unsafe.Pointer) int {
	return int(C.X_X509_NAME_entry_count((*C.X509_NAME)(n)))
}

// X509_NAME_get_entry 返回第 i 个名字条目（内部指针，勿释放）。
//
// X509_NAME_get_entry returns the i-th X509_NAME_ENTRY. It is an internal
// pointer owned by n and must NOT be freed.
func X509_NAME_get_entry(n unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_NAME_get_entry((*C.X509_NAME)(n), C.int(i)))
}

// X509_NAME_ENTRY_nid 返回名字条目的 NID（NidUndef 表示未知）。
//
// X509_NAME_ENTRY_nid returns the NID of entry e, or NidUndef for unknown.
func X509_NAME_ENTRY_nid(e unsafe.Pointer) int {
	return int(C.X_X509_NAME_ENTRY_nid(e))
}

// X509_NAME_ENTRY_value 返回名字条目的 UTF-8 值。
//
// X509_NAME_ENTRY_value returns the UTF-8 string value of e. Returns
// ("", false) when the entry has no data; the returned Go string is
// independent of the OpenSSL buffer.
func X509_NAME_ENTRY_value(e unsafe.Pointer) (string, bool) {
	c := C.X_X509_NAME_ENTRY_value(e)
	if c == nil {
		return "", false
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c), true
}

// X509_NAME_oneline 返回名字的单行文本（如 "/CN=.."）。
//
// X509_NAME_oneline returns the human-readable one-line representation of n
// (e.g. "/CN=foo.example.com/O=Acme"). Returns ("", false) when the C
// helper returns NULL; the resulting buffer is freed internally.
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
//
// X509_NAME_get_text_by_txt returns the text of the first RDN entry whose
// short name matches field (e.g. "CN", "O"). Implemented via OBJ_txt2nid +
// X509_NAME_get_text_by_NID because the C function is a macro in OpenSSL 3.x.
func X509_NAME_get_text_by_txt(n unsafe.Pointer, field string) string {
	nid := OBJ_txt2nid(field)
	if nid == NidUndef {
		return ""
	}
	return X509_NAME_get_text_by_NID(n, nid)
}

// X509_NAME_new 创建新的 X509_NAME。
//
// X509_NAME_new allocates an empty X509_NAME. The caller owns the returned
// pointer and must release it with X509_NAME_free.
func X509_NAME_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_NAME_new())
}

// X509_NAME_free 释放 X509_NAME。
//
// X509_NAME_free releases n. Safe on NULL; the pointer must not be used
// after free.
func X509_NAME_free(n unsafe.Pointer) {
	C.X509_NAME_free((*C.X509_NAME)(n))
}

// X509_NAME_add_entry_by_txt 添加名字条目（field 如 "CN"、"C"、"O"）。
//
// X509_NAME_add_entry_by_txt appends an RDN entry to n using the short-name
// field tag (e.g. "CN", "C", "O") and the given value. The string type is
// MBSTRING_ASC (0x1001).
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
//
// X509_NAME_get_text_by_NID reads the text of the first entry with the given
// NID into a 256-byte stack buffer (truncated for longer values). Returns ""
// when no matching entry exists.
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
//
// X509_new allocates a new empty X509 certificate. The caller owns the
// returned pointer and must release it with X509_free.
func X509_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_new())
}

// X509_free 释放证书对象。
//
// X509_free releases x. Safe on NULL; the pointer must not be used after free.
func X509_free(x unsafe.Pointer) {
	C.X509_free((*C.X509)(x))
}

// X509_set_version 设置证书版本（0=v1，2=v3）。
//
// X509_set_version sets the X.509 version of x (0=v1, 1=v2, 2=v3).
// Returns true on success.
func X509_set_version(x unsafe.Pointer, version int) bool {
	return C.X509_set_version((*C.X509)(x), C.long(version)) == 1
}

// X509_set_serial_int 设置证书序列号（整型）。
//
// X509_set_serial_int sets the X.509 serial number from an int64; negative
// values are accepted but invalid per RFC 5280. Returns true on success.
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
//
// X509_get_serial_int reads the X.509 serial number as an int64 (sign is
// preserved). Returns 0 when the field is missing.
func X509_get_serial_int(x unsafe.Pointer) int64 {
	ai := C.X509_get_serialNumber((*C.X509)(x))
	if ai == nil {
		return 0
	}
	return int64(C.ASN1_INTEGER_get(ai))
}

// ASN1_INTEGER_free 释放 ASN1_INTEGER。
//
// ASN1_INTEGER_free releases ai. Safe on NULL.
func ASN1_INTEGER_free(ai unsafe.Pointer) {
	C.ASN1_INTEGER_free((*C.ASN1_INTEGER)(ai))
}

// ASN1_INTEGER_get 读取 ASN1_INTEGER 整型值（保留符号）。
//
// ASN1_INTEGER_get returns the integer value of ai (sign preserved).
// Returns 0 when ai is NULL.
func ASN1_INTEGER_get(ai unsafe.Pointer) int64 {
	return int64(C.ASN1_INTEGER_get((*C.ASN1_INTEGER)(ai)))
}

// X509_set_issuer_name 设置签发者名字。
//
// X509_set_issuer_name sets the issuer name of x to n; X509_set duplicates n
// internally so the caller retains ownership of n.
func X509_set_issuer_name(x, n unsafe.Pointer) bool {
	return C.X509_set_issuer_name((*C.X509)(x), (*C.X509_NAME)(n)) == 1
}

// X509_set_subject_name 设置主题名字。
//
// X509_set_subject_name sets the subject name of x to n; X509_set duplicates
// n internally so the caller retains ownership of n.
func X509_set_subject_name(x, n unsafe.Pointer) bool {
	return C.X509_set_subject_name((*C.X509)(x), (*C.X509_NAME)(n)) == 1
}

// X509_get_issuer_name 读取签发者名字（内部指针，勿释放）。
//
// X509_get_issuer_name returns the internal issuer-name pointer of x; do NOT
// free it.
func X509_get_issuer_name(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_issuer_name((*C.X509)(x)))
}

// X509_get_subject_name 读取主题名字（内部指针，勿释放）。
//
// X509_get_subject_name returns the internal subject-name pointer of x; do
// NOT free it.
func X509_get_subject_name(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_subject_name((*C.X509)(x)))
}

// X509_set_pubkey 设置证书公钥。
//
// X509_set_pubkey installs pkey as the public key of x; X509_set increments
// the reference count, so the caller retains ownership of pkey.
func X509_set_pubkey(x, pkey unsafe.Pointer) bool {
	return C.X509_set_pubkey((*C.X509)(x), (*C.EVP_PKEY)(pkey)) == 1
}

// X509_get_pubkey 读取证书公钥（返回新引用，调用方负责 EVP_PKEY_free）。
//
// X509_get_pubkey returns a NEW EVP_PKEY reference; the caller MUST release
// it with EVP_PKEY_free.
func X509_get_pubkey(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_pubkey((*C.X509)(x)))
}

// X509_set_not_before 设置生效时间（unix 秒）。
//
// X509_set_not_before sets the notBefore time (unix seconds). Returns true
// when the ASN1_TIME update succeeds.
func X509_set_not_before(x unsafe.Pointer, t int64) bool {
	timePtr := C.X509_getm_notBefore((*C.X509)(x))
	return C.ASN1_TIME_set(timePtr, C.long(t)) != nil
}

// X509_set_not_after 设置过期时间（unix 秒）。
//
// X509_set_not_after sets the notAfter time (unix seconds). Returns true when
// the ASN1_TIME update succeeds.
func X509_set_not_after(x unsafe.Pointer, t int64) bool {
	timePtr := C.X509_getm_notAfter((*C.X509)(x))
	return C.ASN1_TIME_set(timePtr, C.long(t)) != nil
}

// X509_get_not_before 读取生效时间（unix 秒）。
//
// X509_get_not_before reads the notBefore time (unix seconds); returns 0
// when the field is absent.
func X509_get_not_before(x unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_getm_notBefore((*C.X509)(x)))
}

// X509_get_not_after 读取过期时间（unix 秒）。
//
// X509_get_not_after reads the notAfter time (unix seconds); returns 0
// when the field is absent.
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
//
// X509_sign signs x with pkey and the message digest md. Returns true on
// success (non-zero signature length).
func X509_sign(x, pkey, md unsafe.Pointer) bool {
	return C.X509_sign((*C.X509)(x), (*C.EVP_PKEY)(pkey), (*C.EVP_MD)(md)) != 0
}

// X509_verify 使用公钥验证证书签名。
//
// X509_verify checks x's signature using pkey (typically the issuer's public
// key). Returns true on a valid signature.
func X509_verify(x, pkey unsafe.Pointer) bool {
	return C.X509_verify((*C.X509)(x), (*C.EVP_PKEY)(pkey)) == 1
}

// X509V3_EXT_conf_nid 按 NID 与配置值创建扩展对象（如 basicConstraints）。
//
// X509V3_EXT_conf_nid parses the OpenSSL config-format string value and
// builds a new X509_EXTENSION for nid (e.g. "CA:TRUE" for NidBasicConstraints).
// Caller owns the returned extension and must release with X509_EXTENSION_free.
func X509V3_EXT_conf_nid(nid int, value string) unsafe.Pointer {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	return unsafe.Pointer(C.X509V3_EXT_conf_nid(nil, nil, C.int(nid), cVal))
}

// X509_add_ext 向证书追加扩展。
//
// X509_add_ext appends ext to the end of x's extension stack; the -1 flag
// asks OpenSSL to append. X509_add duplicates ext internally so the caller
// retains ownership.
func X509_add_ext(x, ext unsafe.Pointer) bool {
	return C.X509_add_ext((*C.X509)(x), (*C.X509_EXTENSION)(ext), C.int(-1)) == 1
}

// X509_EXTENSION_free 释放扩展对象。
//
// X509_EXTENSION_free releases ext. Safe on NULL; the pointer must not be
// used after free.
func X509_EXTENSION_free(ext unsafe.Pointer) {
	C.X509_EXTENSION_free((*C.X509_EXTENSION)(ext))
}

// X_PEM_read_bio_X509 从 BIO 读取 PEM 证书。
//
// X_PEM_read_bio_X509 (shim) reads a PEM-encoded X509 from bio. Returns
// NULL on parse failure; caller owns the result and must free it with
// X509_free.
func X_PEM_read_bio_X509(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_X509((*C.BIO)(bio)))
}

// X_PEM_write_bio_X509 将证书以 PEM 写入 BIO。
//
// X_PEM_write_bio_X509 (shim) writes x to bio in PEM form. Returns true on
// success.
func X_PEM_write_bio_X509(bio unsafe.Pointer, x unsafe.Pointer) bool {
	return C.X_PEM_write_bio_X509((*C.BIO)(bio), (*C.X509)(x)) == 1
}

// X509_REQ_new 创建新的证书签名请求。
//
// X509_REQ_new allocates a new empty X509_REQ (PKCS#10 CSR). Caller owns it
// and must release it with X509_REQ_free.
func X509_REQ_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_REQ_new())
}

// X509_REQ_free 释放证书签名请求。
//
// X509_REQ_free releases the X509_REQ. Safe on NULL; the pointer must not be
// used after free.
func X509_REQ_free(r unsafe.Pointer) {
	C.X509_REQ_free((*C.X509_REQ)(r))
}

// X509_REQ_set_pubkey 设置 CSR 公钥。
//
// X509_REQ_set_pubkey installs pkey as the CSR's public key. The reference
// count is incremented internally so the caller retains ownership of pkey.
func X509_REQ_set_pubkey(r, pkey unsafe.Pointer) bool {
	return C.X509_REQ_set_pubkey((*C.X509_REQ)(r), (*C.EVP_PKEY)(pkey)) == 1
}

// X509_REQ_set_subject_name 设置 CSR 主题。
//
// X509_REQ_set_subject_name sets the CSR's subject name; the name is duplicated
// internally.
func X509_REQ_set_subject_name(r, n unsafe.Pointer) bool {
	return C.X509_REQ_set_subject_name((*C.X509_REQ)(r), (*C.X509_NAME)(n)) == 1
}

// X509_REQ_sign 对 CSR 签名。成功返回签名长度（非 0）。
//
// X509_REQ_sign signs r with pkey and digest md. Returns true on success.
func X509_REQ_sign(r, pkey, md unsafe.Pointer) bool {
	return C.X509_REQ_sign((*C.X509_REQ)(r), (*C.EVP_PKEY)(pkey), (*C.EVP_MD)(md)) != 0
}

// X509_REQ_verify 验证 CSR 签名（使用其自身公钥）。
//
// X509_REQ_verify verifies the CSR signature; pkey is typically the public
// key carried inside r.
func X509_REQ_verify(r, pkey unsafe.Pointer) bool {
	return C.X509_REQ_verify((*C.X509_REQ)(r), (*C.EVP_PKEY)(pkey)) == 1
}

// X509_REQ_get_pubkey 读取 CSR 公钥（返回新引用）。
//
// X509_REQ_get_pubkey returns a NEW EVP_PKEY reference; caller MUST release
// it with EVP_PKEY_free.
func X509_REQ_get_pubkey(r unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_REQ_get_pubkey((*C.X509_REQ)(r)))
}

// X509_REQ_get_subject_name 读取 CSR 主题（内部指针）。
//
// X509_REQ_get_subject_name returns the internal subject-name pointer of r;
// do NOT free it.
func X509_REQ_get_subject_name(r unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_REQ_get_subject_name((*C.X509_REQ)(r)))
}

// I2d_X509_REQ_INFO 将 CSR 的 CertificationRequestInfo 编码为 DER（签名覆盖的数据）。
//
// I2d_X509_REQ_INFO serializes the CertificationRequestInfo part of r (the
// portion covered by the signature) to DER. Returns (bytes, true) on success.
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
//
// X509_REQ_get0_signature returns the raw signature bytes from r. Returns
// (nil, false) when no signature is present.
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

// X509_REQ_get_signature_info 返回 CSR 签名的原始字节、签名算法 NID 与签名算法 OID（点分文本）。
// 任一字段不可用时返回空值（nil / 0 / ""），永不返回错误。
//
// X509_REQ_get_signature_info returns the raw signature bytes, the
// signature algorithm NID, and the signature algorithm OID as dotted
// text from r. When a field is unavailable the corresponding zero
// value (nil / 0 / "") is returned; the call never reports an error.
func X509_REQ_get_signature_info(r unsafe.Pointer) ([]byte, int, string) {
	var psig *C.ASN1_BIT_STRING
	var palg *C.X509_ALGOR
	C.X509_REQ_get0_signature((*C.X509_REQ)(r), &psig, &palg)

	var sig []byte
	if psig != nil {
		length := C.ASN1_STRING_length((*C.ASN1_STRING)(psig))
		data := C.ASN1_STRING_get0_data((*C.ASN1_STRING)(psig))
		if length > 0 && data != nil {
			sig = C.GoBytes(unsafe.Pointer(data), C.int(length))
		}
	}

	var nid int
	var oid string
	if palg != nil {
		var paobj *C.ASN1_OBJECT
		var pptype C.int
		var ppval unsafe.Pointer
		C.X509_ALGOR_get0(&paobj, &pptype, &ppval, palg)
		if paobj != nil {
			nid = int(C.OBJ_obj2nid(paobj))
			n := C.OBJ_obj2txt(nil, 0, paobj, C.int(1))
			if n > 0 {
				buf := make([]C.char, n+1)
				C.OBJ_obj2txt(&buf[0], n+1, paobj, C.int(1))
				oid = C.GoString(&buf[0])
			}
		}
	}
	return sig, nid, oid
}

// X509_get_signature_info 返回证书签名的原始字节、签名算法 NID 与签名算法 OID（点分文本）。
// 任一字段不可用时返回空值（nil / 0 / ""），永不返回错误。
//
// X509_get_signature_info returns the raw signature bytes, the signature
// algorithm NID, and the signature algorithm OID as dotted text (for
// example "1.2.156.10197.1.501"). When a field is unavailable the
// corresponding zero value (nil / 0 / "") is returned; the call never
// reports an error.
func X509_get_signature_info(x unsafe.Pointer) ([]byte, int, string) {
	var psig *C.ASN1_BIT_STRING
	var palg *C.X509_ALGOR
	C.X509_get0_signature(&psig, &palg, (*C.X509)(x))

	var sig []byte
	if psig != nil {
		length := C.ASN1_STRING_length((*C.ASN1_STRING)(psig))
		data := C.ASN1_STRING_get0_data((*C.ASN1_STRING)(psig))
		if length > 0 && data != nil {
			sig = C.GoBytes(unsafe.Pointer(data), C.int(length))
		}
	}

	nid := int(C.X509_get_signature_nid((*C.X509)(x)))

	var oid string
	if palg != nil {
		var paobj *C.ASN1_OBJECT
		var pptype C.int
		var ppval unsafe.Pointer
		C.X509_ALGOR_get0(&paobj, &pptype, &ppval, palg)
		if paobj != nil {
			n := C.OBJ_obj2txt(nil, 0, paobj, C.int(1))
			if n > 0 {
				buf := make([]C.char, n+1)
				C.OBJ_obj2txt(&buf[0], n+1, paobj, C.int(1))
				oid = C.GoString(&buf[0])
			}
		}
	}
	return sig, nid, oid
}

// X_PEM_read_bio_X509_REQ 从 BIO 读取 PEM CSR。
//
// X_PEM_read_bio_X509_REQ (shim) reads a PEM-encoded PKCS#10 CSR from bio.
// Returns NULL on parse failure; caller owns the X509_REQ and must free it.
func X_PEM_read_bio_X509_REQ(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_X509_REQ((*C.BIO)(bio)))
}

// X_PEM_write_bio_X509_REQ 将 CSR 以 PEM 写入 BIO。
//
// X_PEM_write_bio_X509_REQ (shim) writes r to bio in PEM form. Returns true
// on success.
func X_PEM_write_bio_X509_REQ(bio unsafe.Pointer, r unsafe.Pointer) bool {
	return C.X_PEM_write_bio_X509_REQ((*C.BIO)(bio), (*C.X509_REQ)(r)) == 1
}

// X509V3_EXT_conf_nid_ctx 带 X509V3_CTX 创建并追加扩展（SKID/AKID 需要 ctx）。
// subject/issuer 可传 nil（分别用于 SKID 的 subject 公钥、AKID 的 issuer 证书）。
//
// X509V3_EXT_conf_nid_ctx builds an extension on target using the subject
// / issuer context (needed for SKID / AKID). Pass nil for subject or issuer
// when the OID does not require them. Returns true on success.
func X509V3_EXT_conf_nid_ctx(target, subject, issuer unsafe.Pointer, nid int, value string) bool {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	return C.X_X509V3_EXT_conf_nid_ctx((*C.X509)(target),
		(*C.X509)(subject), (*C.X509)(issuer), C.int(nid), cVal) == 1
}

// X509V3_EXT_conf_nid_crl 在 CRL 上创建并追加通用扩展（无 ctx）。
//
// X509V3_EXT_conf_nid_crl builds a new X509_EXTENSION for nid on a CRL
// using the OpenSSL config-format value. The extension is added in place.
// Returns true on success.
func X509V3_EXT_conf_nid_crl(crl unsafe.Pointer, nid int, value string) bool {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	ext := C.X509V3_EXT_conf_nid(nil, nil, C.int(nid), cVal)
	if ext == nil {
		return false
	}
	ok := C.X509_CRL_add_ext((*C.X509_CRL)(crl), ext, C.int(-1)) == 1
	C.X509_EXTENSION_free(ext)
	return ok
}

// X509_CRL_set_crl_number 设置 CRL Number 扩展（值为整型）。
//
// X509_CRL_set_crl_number sets the CRL Number extension to value.
// Returns true on success.
func X509_CRL_set_crl_number(crl unsafe.Pointer, value int64) bool {
	ai := C.ASN1_INTEGER_new()
	if ai == nil {
		return false
	}
	defer C.ASN1_INTEGER_free(ai)
	if C.ASN1_INTEGER_set(ai, C.long(value)) != 1 {
		return false
	}
	ext := C.X509V3_EXT_i2d(C.int(NidCrlNumber), C.int(0), unsafe.Pointer(ai))
	if ext == nil {
		return false
	}
	ok := C.X509_CRL_add_ext((*C.X509_CRL)(crl), ext, C.int(-1)) == 1
	C.X509_EXTENSION_free(ext)
	return ok
}

// X509V3_EXT_conf_nid_ctx_crl 在 CRL 上创建并追加需要 X509V3_CTX 的扩展（CRL 的 AKID）。
//
// X509V3_EXT_conf_nid_ctx_crl builds an extension on a CRL target using
// the issuer context (needed for CRL AKID). Returns true on success.
func X509V3_EXT_conf_nid_ctx_crl(target, issuer unsafe.Pointer, nid int, value string) bool {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	return C.X_X509V3_EXT_conf_nid_ctx_crl((*C.X509_CRL)(target),
		(*C.X509)(issuer), C.int(nid), cVal) == 1
}

// X509_get_version 返回证书版本（0=v1，1=v2，2=v3）。
//
// X509_get_version returns the X.509 version of x as 0=v1, 1=v2, 2=v3.
func X509_get_version(x unsafe.Pointer) int {
	return int(C.X509_get_version((*C.X509)(x)))
}

// X509_get_ext_count 返回证书扩展数量。
//
// X509_get_ext_count returns the number of extensions on x (0 when x has
// no extensions).
func X509_get_ext_count(x unsafe.Pointer) int {
	return int(C.X509_get_ext_count((*C.X509)(x)))
}

// X509_get_ext 返回第 i 个扩展（内部指针，勿释放）。
//
// X509_get_ext returns the i-th extension of x as an internal pointer; do
// NOT free it.
func X509_get_ext(x unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X509_get_ext((*C.X509)(x), C.int(i)))
}

// X509_EXTENSION_get_object 返回扩展 OID（内部指针）。
//
// X509_EXTENSION_get_object returns the internal ASN1_OBJECT pointer for
// the extension OID; do NOT free it.
func X509_EXTENSION_get_object(e unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_EXTENSION_get_object((*C.X509_EXTENSION)(e)))
}

// X509_EXTENSION_get_critical 返回扩展 critical 标志。
//
// X509_EXTENSION_get_critical returns 1 when the extension has the critical
// bit set, 0 otherwise.
func X509_EXTENSION_get_critical(e unsafe.Pointer) int {
	return int(C.X509_EXTENSION_get_critical((*C.X509_EXTENSION)(e)))
}

// X509_EXTENSION_get_data 返回扩展数据的 ASN1_OCTET_STRING（内部指针）。
//
// X509_EXTENSION_get_data returns the internal ASN1_OCTET_STRING holding
// the extension value; do NOT free it (use ASN1_STRING_data_bytes to copy).
func X509_EXTENSION_get_data(e unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_EXTENSION_get_data((*C.X509_EXTENSION)(e)))
}

// ASN1_STRING_data_bytes 返回 ASN1_STRING 的原始字节（复制）。
//
// ASN1_STRING_data_bytes copies the raw bytes of s into a fresh Go slice.
// Returns nil when the string is empty or the C pointer is NULL.
func ASN1_STRING_data_bytes(s unsafe.Pointer) []byte {
	length := C.ASN1_STRING_length((*C.ASN1_STRING)(s))
	data := C.ASN1_STRING_get0_data((*C.ASN1_STRING)(s))
	if length <= 0 || data == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(length))
}

// X509_digest 计算证书指纹。md 为摘要算法描述符。
//
// X509_digest computes the digest of the DER-encoded certificate using md
// (e.g. EVP_sha256). Returns (nil, false) on failure; otherwise the digest
// bytes (up to 64 bytes in this helper).
func X509_digest(x, md unsafe.Pointer) ([]byte, bool) {
	var buf [64]C.uchar
	var n C.uint
	if C.X509_digest((*C.X509)(x), (*C.EVP_MD)(md), &buf[0], &n) != 1 {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), C.int(n)), true
}

// I2d_X509 将证书编码为 DER。
//
// I2d_X509 serializes x to DER. Returns (bytes, true) on success or
// (nil, false) when the encoder reports a non-positive length.
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
//
// D2i_X509 parses a certificate from DER bytes. Returns NULL on empty input
// or parse failure; caller owns the result and must free it with X509_free.
// The Go slice is first memcpy'd into C heap to avoid the cgo "Go pointer
// to Go pointer" rule.
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
//
// I2d_X509_REQ serializes r to DER. Returns (bytes, true) on success.
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
//
// D2i_X509_REQ parses a PKCS#10 CSR from DER bytes. Returns NULL on empty
// input or parse failure; caller owns the result.
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
//
// X509_get_san returns the Subject Alternative Name GENERAL_NAMES stack, or
// nil if the SAN extension is absent. Caller owns the returned stack and
// must release it with X509_GENERAL_NAMES_free.
func X509_get_san(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_san((*C.X509)(x)))
}

// X509_GENERAL_NAMES_free 释放 GENERAL_NAMES 栈。
//
// X509_GENERAL_NAMES_free releases the stack AND all entries.
func X509_GENERAL_NAMES_free(sk unsafe.Pointer) {
	C.X_GENERAL_NAMES_free(sk)
}

// X509_GENERAL_NAMES_num 返回 SAN 条目数。
//
// X509_GENERAL_NAMES_num returns the number of SAN entries in the stack.
func X509_GENERAL_NAMES_num(sk unsafe.Pointer) int {
	return int(C.X_GENERAL_NAMES_num(sk))
}

// X509_GENERAL_NAMES_value 返回第 i 个 GENERAL_NAME（内部指针）。
//
// X509_GENERAL_NAMES_value returns the i-th GENERAL_NAME as an internal
// pointer; do NOT free it.
func X509_GENERAL_NAMES_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_GENERAL_NAMES_value(sk, C.int(i)))
}

// X509_GENERAL_NAME_type 返回 GENERAL_NAME 类型（Gen* 常量）。
//
// X509_GENERAL_NAME_type returns the type tag of gn (one of the Gen* constants).
func X509_GENERAL_NAME_type(gn unsafe.Pointer) int {
	return int(C.X_GENERAL_NAME_type(gn))
}

// X509_GENERAL_NAME_to_string 返回 GENERAL_NAME 的值文本（如 "example.com"）。
//
// X509_GENERAL_NAME_to_string returns the human-readable value of gn (e.g.
// the hostname for a dNSName, the IP literal for an iPAddress). Returns ""
// when the helper returns NULL.
func X509_GENERAL_NAME_to_string(gn unsafe.Pointer) string {
	c := C.X_GENERAL_NAME_to_string(gn)
	if c == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c)
}

// X509_get_key_usage 返回 KeyUsage 扩展的 ASN1_BIT_STRING（无则 nil）。调用方负责 X509_ASN1_BIT_STRING_free。
//
// X509_get_key_usage returns the KeyUsage extension's ASN1_BIT_STRING, or
// nil if absent. Caller owns the result and must release it with
// X509_ASN1_BIT_STRING_free.
func X509_get_key_usage(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_key_usage((*C.X509)(x)))
}

// X509_ASN1_BIT_STRING_free 释放 ASN1_BIT_STRING。
//
// X509_ASN1_BIT_STRING_free releases the BIT STRING returned by
// X509_get_key_usage or similar helpers.
func X509_ASN1_BIT_STRING_free(bs unsafe.Pointer) {
	C.X_ASN1_BIT_STRING_free(bs)
}

// ASN1_BIT_STRING_get_bit 读取位串第 bit 位。
//
// ASN1_BIT_STRING_get_bit returns true when the bit-th bit of bs is set
// (bit numbering matches RFC 5280: 0=digitalSignature, 1=nonRepudiation,
// ...).
func ASN1_BIT_STRING_get_bit(bs unsafe.Pointer, bit int) bool {
	return C.ASN1_BIT_STRING_get_bit((*C.ASN1_BIT_STRING)(bs), C.int(bit)) == 1
}

// X509_get_eku 返回 EKU 扩展的 EXTENDED_KEY_USAGE 栈（无则 nil）。调用方负责 X509_EXTENDED_KEY_USAGE_free。
//
// X509_get_eku returns the ExtendedKeyUsage stack, or nil if absent. Caller
// owns the result and must release it with X509_EXTENDED_KEY_USAGE_free.
func X509_get_eku(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_eku((*C.X509)(x)))
}

// X509_EXTENDED_KEY_USAGE_free 释放 EKU 栈。
//
// X509_EXTENDED_KEY_USAGE_free releases the stack AND all entries.
func X509_EXTENDED_KEY_USAGE_free(sk unsafe.Pointer) {
	C.X_EXTENDED_KEY_USAGE_free(sk)
}

// X509_EXTENDED_KEY_USAGE_num 返回 EKU 条目数。
//
// X509_EXTENDED_KEY_USAGE_num returns the number of EKU entries.
func X509_EXTENDED_KEY_USAGE_num(sk unsafe.Pointer) int {
	return int(C.X_EXTENDED_KEY_USAGE_num(sk))
}

// X509_EXTENDED_KEY_USAGE_value 返回第 i 个 EKU 的 ASN1_OBJECT（内部指针）。
//
// X509_EXTENDED_KEY_USAGE_value returns the i-th EKU as an internal ASN1_OBJECT
// pointer; do NOT free it.
func X509_EXTENDED_KEY_USAGE_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_EXTENDED_KEY_USAGE_value(sk, C.int(i)))
}

// OBJ_to_string 返回 ASN1_OBJECT 的名称或 OID 文本。
//
// OBJ_to_string returns the long name for the ASN1_OBJECT, falling back to
// the numeric OID. Returns "" when the C helper returns NULL.
func OBJ_to_string(o unsafe.Pointer) string {
	c := C.X_OBJ_to_string(o)
	if c == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c)
}

// X509_get_basic_constraints 返回 BasicConstraints 扩展（无则 nil）。调用方负责 X509_BASIC_CONSTRAINTS_free。
//
// X509_get_basic_constraints returns the BasicConstraints extension, or nil
// if absent. Caller owns the result and must release it with
// X509_BASIC_CONSTRAINTS_free.
func X509_get_basic_constraints(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_get_basic_constraints((*C.X509)(x)))
}

// X509_BASIC_CONSTRAINTS_free 释放 BASIC_CONSTRAINTS。
//
// X509_BASIC_CONSTRAINTS_free releases the BASIC_CONSTRAINTS returned by
// X509_get_basic_constraints.
func X509_BASIC_CONSTRAINTS_free(bc unsafe.Pointer) {
	C.X_BASIC_CONSTRAINTS_free(bc)
}

// X509_BASIC_CONSTRAINTS_ca 返回 BasicConstraints 的 CA 标志。
//
// X509_BASIC_CONSTRAINTS_ca returns 1 when the cA boolean is TRUE, 0
// otherwise (or when bc is NULL).
func X509_BASIC_CONSTRAINTS_ca(bc unsafe.Pointer) int {
	return int(C.X_BASIC_CONSTRAINTS_ca(bc))
}

// X509_BASIC_CONSTRAINTS_pathlen 返回 pathlen（无约束为 -1）。
//
// X509_BASIC_CONSTRAINTS_pathlen returns the pathLenConstraint value
// (RFC 5280: -1 means "no constraint").
func X509_BASIC_CONSTRAINTS_pathlen(bc unsafe.Pointer) int64 {
	return int64(C.X_BASIC_CONSTRAINTS_pathlen(bc))
}

// X509_get0_subject_key_id 返回 SKID 字节（内部指针，勿释放）。
//
// X509_get0_subject_key_id returns a copy of the SubjectKeyIdentifier bytes,
// or nil when the extension is absent. The OpenSSL-internal pointer is NOT
// exposed.
func X509_get0_subject_key_id(x unsafe.Pointer) []byte {
	c := C.X509_get0_subject_key_id((*C.X509)(x))
	if c == nil {
		return nil
	}
	return ASN1_STRING_data_bytes(unsafe.Pointer(c))
}

// X509_get0_authority_key_id 返回 AKID 中 keyid 字节（内部指针，勿释放）。
//
// X509_get0_authority_key_id returns a copy of the AuthorityKeyIdentifier
// keyid bytes, or nil when the AKID extension has no keyid component.
func X509_get0_authority_key_id(x unsafe.Pointer) []byte {
	c := C.X509_get0_authority_key_id((*C.X509)(x))
	if c == nil {
		return nil
	}
	return ASN1_STRING_data_bytes(unsafe.Pointer(c))
}

// X509_sk_X509_EXTENSION_new_null 创建空的扩展栈。
//
// X509_sk_X509_EXTENSION_new_null allocates an empty X509_EXTENSION stack.
// Caller owns the returned stack.
func X509_sk_X509_EXTENSION_new_null() unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_EXTENSION_new_null())
}

// X509_sk_X509_EXTENSION_push 向扩展栈压入扩展（栈不拥有该扩展）。
//
// X509_sk_X509_EXTENSION_push appends ext to sk. The stack does NOT take
// ownership of ext.
func X509_sk_X509_EXTENSION_push(sk, ext unsafe.Pointer) bool {
	return C.X_sk_X509_EXTENSION_push(sk, ext) == 1
}

// X509_sk_X509_EXTENSION_free 释放扩展栈（不释放元素）。
//
// X509_sk_X509_EXTENSION_free releases the stack container; the caller still
// owns the pushed elements.
func X509_sk_X509_EXTENSION_free(sk unsafe.Pointer) {
	C.X_sk_X509_EXTENSION_free(sk)
}

// X509_sk_X509_EXTENSION_pop_free 释放扩展栈并释放全部元素。
//
// X509_sk_X509_EXTENSION_pop_free releases the stack AND every element via
// X509_EXTENSION_free.
func X509_sk_X509_EXTENSION_pop_free(sk unsafe.Pointer) {
	C.X_sk_X509_EXTENSION_pop_free(sk)
}

// X509_sk_X509_EXTENSION_num 返回扩展栈条目数。
//
// X509_sk_X509_EXTENSION_num returns the number of entries in sk.
func X509_sk_X509_EXTENSION_num(sk unsafe.Pointer) int {
	return int(C.X_sk_X509_EXTENSION_num(sk))
}

// X509_sk_X509_EXTENSION_value 返回扩展栈第 i 个扩展（内部指针）。
//
// X509_sk_X509_EXTENSION_value returns the i-th X509_EXTENSION as an
// internal pointer; do NOT free it.
func X509_sk_X509_EXTENSION_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_EXTENSION_value(sk, C.int(i)))
}

// X509_REQ_add_extensions 为 CSR 添加扩展（须在 Sign 之前调用）。
//
// X509_REQ_add_extensions copies the extensions from sk into r. Must be
// called BEFORE X509_REQ_sign so the extensions are covered by the signature.
func X509_REQ_add_extensions(r, sk unsafe.Pointer) bool {
	return C.X_X509_REQ_add_extensions((*C.X509_REQ)(r), sk) == 1
}

// X509_REQ_get_extensions 返回 CSR 中的扩展栈（调用方负责 X509_sk_X509_EXTENSION_pop_free）。
//
// X509_REQ_get_extensions returns a NEW extension stack; the caller owns it
// and must release the stack and its elements with
// X509_sk_X509_EXTENSION_pop_free.
func X509_REQ_get_extensions(r unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_X509_REQ_get_extensions((*C.X509_REQ)(r)))
}

// X509_REQ_set_challenge_password 设置 CSR 挑战密码（PKCS#9 challengePassword 属性）。
//
// X509_REQ_set_challenge_password stores the PKCS#9 challengePassword
// attribute on r. Returns true on success.
func X509_REQ_set_challenge_password(r unsafe.Pointer, pwd string) bool {
	c := C.CString(pwd)
	defer C.free(unsafe.Pointer(c))
	return C.X_X509_REQ_set_challenge_password((*C.X509_REQ)(r), c) == 1
}

// X509_REQ_get_challenge_password 返回 CSR 挑战密码（无则为空串）。
//
// X509_REQ_get_challenge_password returns the PKCS#9 challengePassword
// stored on r, or "" when no challenge password is set.
func X509_REQ_get_challenge_password(r unsafe.Pointer) string {
	c := C.X_X509_REQ_get_challenge_password((*C.X509_REQ)(r))
	if c == nil {
		return ""
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(c))
	return C.GoString(c)
}

// NidCrlReason 为 CRL 吊销原因扩展 NID（来自 obj_mac.h）。
//
// NidCrlReason is the OpenSSL NID for the CRL Reason Code extension (141),
// used by X509_REVOKED_crl_reason.
const NidCrlReason = 141

// X509_V_ERR_* 证书链验证错误码（来自 x509_vfy.h 宏）。
//
// X509V* mirror the OpenSSL X509_V_ERR_* error codes returned by
// X509_STORE_CTX_get_error. X509VOK == 0 means success.
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
//
// X509VFlag* are the chain-verification flags accepted by
// X509_STORE_set_flags: CRLCheck enables CRL checks for the EE cert,
// CRLCheckAll enables CRL checks for the full chain.
const (
	X509VFlagCRLCheck    = 0x4
	X509VFlagCRLCheckAll = 0x8
)

// X509_dup 复制证书（返回新引用，调用方负责 X509_free）。
//
// X509_dup duplicates x. Caller owns the returned X509 and must free it
// with X509_free.
func X509_dup(x unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_dup((*C.X509)(x)))
}

// X509_STORE_new 创建证书存储。
//
// X509_STORE_new allocates an empty trust store (X509_STORE). Caller owns it
// and must release it with X509_STORE_free.
func X509_STORE_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_new())
}

// X509_STORE_free 释放证书存储。
//
// X509_STORE_free releases s. Safe on NULL; the pointer must not be used
// after free.
func X509_STORE_free(s unsafe.Pointer) {
	C.X509_STORE_free((*C.X509_STORE)(s))
}

// X509_STORE_add_cert 向存储添加信任证书（存储内部持引用，调用方仍拥有证书）。
//
// X509_STORE_add_cert adds x as a trust anchor. The store increments the
// reference count; the caller retains ownership of x.
func X509_STORE_add_cert(s, x unsafe.Pointer) bool {
	return C.X509_STORE_add_cert((*C.X509_STORE)(s), (*C.X509)(x)) == 1
}

// X509_STORE_add_crl 向存储添加 CRL（存储内部持引用）。
//
// X509_STORE_add_crl adds crl to the store. The store increments the
// reference count; the caller retains ownership of crl.
func X509_STORE_add_crl(s, crl unsafe.Pointer) bool {
	return C.X509_STORE_add_crl((*C.X509_STORE)(s), (*C.X509_CRL)(crl)) == 1
}

// X509_STORE_set_flags 设置存储验证标志。
//
// X509_STORE_set_flags sets verification flags (X509VFlag* constants) on s.
func X509_STORE_set_flags(s unsafe.Pointer, flags uint64) bool {
	return C.X509_STORE_set_flags((*C.X509_STORE)(s), C.ulong(flags)) == 1
}

// X509_STORE_CTX_new 创建验证上下文。
//
// X509_STORE_CTX_new allocates an empty verification context. Caller owns it
// and must release it with X509_STORE_CTX_free after X509_STORE_CTX_init.
func X509_STORE_CTX_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_CTX_new())
}

// X509_STORE_CTX_free 释放验证上下文。
//
// X509_STORE_CTX_free releases ctx. Safe on NULL; the pointer must not be
// used after free.
func X509_STORE_CTX_free(ctx unsafe.Pointer) {
	C.X509_STORE_CTX_free((*C.X509_STORE_CTX)(ctx))
}

// X509_STORE_CTX_init 初始化验证上下文（store 为信任存储，cert 为待验证证书）。
//
// X509_STORE_CTX_init prepares ctx to verify cert against store. Caller still
// owns store and cert; pass NULL for the untrusted chain and use
// X509_STORE_CTX_set0_untrusted afterwards.
func X509_STORE_CTX_init(ctx, store, cert unsafe.Pointer) bool {
	return C.X509_STORE_CTX_init((*C.X509_STORE_CTX)(ctx),
		(*C.X509_STORE)(store), (*C.X509)(cert), nil) == 1
}

// X509_STORE_CTX_set0_untrusted 设置中间证书链（所有权转移给 ctx，勿再释放）。
//
// X509_STORE_CTX_set0_untrusted transfers ownership of sk (an X509 stack)
// to ctx. The caller MUST NOT free sk afterwards.
func X509_STORE_CTX_set0_untrusted(ctx, sk unsafe.Pointer) {
	C.X_X509_STORE_CTX_set0_untrusted((*C.X509_STORE_CTX)(ctx), sk)
}

// X509_verify_cert 验证证书链（1=通过，0=失败，-1=内部错误）。
//
// X509_verify_cert runs the chain verification: 1 = success, 0 = verification
// failure (consult X509_STORE_CTX_get_error), -1 = internal error.
func X509_verify_cert(ctx unsafe.Pointer) int {
	return int(C.X509_verify_cert((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get_error 返回验证错误码。
//
// X509_STORE_CTX_get_error returns the X509V* error code from the last
// verification attempt.
func X509_STORE_CTX_get_error(ctx unsafe.Pointer) int {
	return int(C.X509_STORE_CTX_get_error((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get_error_depth 返回出错深度。
//
// X509_STORE_CTX_get_error_depth returns the depth at which the verification
// failure occurred (0 = EE cert).
func X509_STORE_CTX_get_error_depth(ctx unsafe.Pointer) int {
	return int(C.X509_STORE_CTX_get_error_depth((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get_current_cert 返回出错证书（内部指针，勿释放）。
//
// X509_STORE_CTX_get_current_cert returns the cert that triggered the error;
// internal pointer, do NOT free.
func X509_STORE_CTX_get_current_cert(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_CTX_get_current_cert((*C.X509_STORE_CTX)(ctx)))
}

// X509_STORE_CTX_get0_chain 返回已验证链（内部栈，勿释放）。
//
// X509_STORE_CTX_get0_chain returns the internal verified chain stack; do
// NOT free.
func X509_STORE_CTX_get0_chain(ctx unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_STORE_CTX_get0_chain((*C.X509_STORE_CTX)(ctx)))
}

// X509_verify_cert_error_string 返回验证错误码对应的描述。
//
// X509_verify_cert_error_string returns the human-readable description for
// an X509V* error code, or "" when the C string is NULL.
func X509_verify_cert_error_string(code int) string {
	c := C.X509_verify_cert_error_string(C.long(code))
	if c == nil {
		return ""
	}
	return C.GoString(c)
}

// X509_sk_X509_new_null 创建 X509 栈。
//
// X509_sk_X509_new_null allocates an empty X509 stack. Caller owns it.
func X509_sk_X509_new_null() unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_new_null())
}

// X509_sk_X509_push 向 X509 栈压入证书（栈不拥有元素）。
//
// X509_sk_X509_push appends x to sk. The stack does NOT take ownership of x.
func X509_sk_X509_push(sk, x unsafe.Pointer) bool {
	return C.X_sk_X509_push(sk, x) == 1
}

// X509_sk_X509_free 释放 X509 栈（不释放元素）。
//
// X509_sk_X509_free releases the stack container only.
func X509_sk_X509_free(sk unsafe.Pointer) {
	C.X_sk_X509_free(sk)
}

// X509_sk_X509_pop_free 释放 X509 栈并释放全部元素。
//
// X509_sk_X509_pop_free releases the stack AND every element via X509_free.
func X509_sk_X509_pop_free(sk unsafe.Pointer) {
	C.X_sk_X509_pop_free(sk)
}

// X509_sk_X509_num 返回 X509 栈条目数。
//
// X509_sk_X509_num returns the number of entries in sk.
func X509_sk_X509_num(sk unsafe.Pointer) int {
	return int(C.X_sk_X509_num(sk))
}

// X509_sk_X509_value 返回 X509 栈第 i 个证书（内部指针）。
//
// X509_sk_X509_value returns the i-th X509 as an internal pointer; do NOT free.
func X509_sk_X509_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_value(sk, C.int(i)))
}

// X509_NAME_cmp 比较两个名字（0=相等）。
//
// X509_NAME_cmp compares a and b: returns 0 for equal, non-zero otherwise.
func X509_NAME_cmp(a, b unsafe.Pointer) int {
	return int(C.X509_NAME_cmp((*C.X509_NAME)(a), (*C.X509_NAME)(b)))
}

// D2i_X509_CRL 从 DER 解析 CRL。
//
// D2i_X509_CRL parses an X509_CRL from DER bytes. Returns NULL on empty
// input or parse failure; caller owns the result and must free it with
// X509_CRL_free.
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
//
// I2d_X509_CRL serializes crl to DER. Returns (bytes, true) on success.
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
//
// X_PEM_read_bio_X509_CRL (shim) reads a PEM-encoded CRL from bio. Returns
// NULL on parse failure; caller owns the X509_CRL.
func X_PEM_read_bio_X509_CRL(bio unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X_PEM_read_bio_X509_CRL((*C.BIO)(bio)))
}

// X_PEM_write_bio_X509_CRL 将 CRL 以 PEM 写入 BIO。
//
// X_PEM_write_bio_X509_CRL (shim) writes crl to bio in PEM form. Returns true
// on success.
func X_PEM_write_bio_X509_CRL(bio unsafe.Pointer, crl unsafe.Pointer) bool {
	return C.X_PEM_write_bio_X509_CRL((*C.BIO)(bio), (*C.X509_CRL)(crl)) == 1
}

// X509_CRL_free 释放 CRL。
//
// X509_CRL_free releases crl. Safe on NULL; the pointer must not be used
// after free.
func X509_CRL_free(crl unsafe.Pointer) {
	C.X509_CRL_free((*C.X509_CRL)(crl))
}

// X509_CRL_new 创建空 CRL。
//
// X509_CRL_new allocates a new empty X509_CRL (v1 by default; caller may
// upgrade to v2 via X509_CRL_set_version). Caller owns the result and
// must release it with X509_CRL_free.
func X509_CRL_new() unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_new())
}

// X509_CRL_set_version 设置 CRL 版本（0=v1，1=v2）。
//
// X509_CRL_set_version sets the CRL version (0 for v1, 1 for v2).
// Returns true on success.
func X509_CRL_set_version(crl unsafe.Pointer, version int) bool {
	return C.X509_CRL_set_version((*C.X509_CRL)(crl), C.long(version)) == 1
}

// X509_CRL_set_issuer_name 设置 CRL 签发者名字（X509_CRL 复制其内部指针）。
//
// X509_CRL_set_issuer_name sets the issuer name of crl; X509_CRL duplicates
// the X509_NAME internally so caller still owns name.
func X509_CRL_set_issuer_name(crl, name unsafe.Pointer) bool {
	return C.X509_CRL_set_issuer_name((*C.X509_CRL)(crl),
		(*C.X509_NAME)(name)) == 1
}

// X509_CRL_set1_lastUpdate 设置 CRL thisUpdate 时间（unix 秒）。
//
// X509_CRL_set1_lastUpdate sets the thisUpdate field of crl from a unix
// timestamp (seconds).
func X509_CRL_set1_lastUpdate(crl unsafe.Pointer, unix int64) bool {
	tt := C.ASN1_TIME_new()
	if tt == nil {
		return false
	}
	defer C.ASN1_TIME_free(tt)
	if C.ASN1_TIME_set(tt, C.time_t(unix)) == nil {
		return false
	}
	return C.X509_CRL_set1_lastUpdate((*C.X509_CRL)(crl), tt) == 1
}

// X509_CRL_set1_nextUpdate 设置 CRL nextUpdate 时间（unix 秒）。
//
// X509_CRL_set1_nextUpdate sets the nextUpdate field of crl from a unix
// timestamp (seconds).
func X509_CRL_set1_nextUpdate(crl unsafe.Pointer, unix int64) bool {
	tt := C.ASN1_TIME_new()
	if tt == nil {
		return false
	}
	defer C.ASN1_TIME_free(tt)
	if C.ASN1_TIME_set(tt, C.time_t(unix)) == nil {
		return false
	}
	return C.X509_CRL_set1_nextUpdate((*C.X509_CRL)(crl), tt) == 1
}

// X509_CRL_sign 用签名密钥与摘要算法对 CRL 签名。
//
// X509_CRL_sign signs crl with pkey and the message digest md. Returns
// true on success.
func X509_CRL_sign(crl, pkey, md unsafe.Pointer) bool {
	return C.X509_CRL_sign((*C.X509_CRL)(crl),
		(*C.EVP_PKEY)(pkey), (*C.EVP_MD)(md)) != 0
}

// X509_CRL_get_version 返回 CRL 版本。
//
// X509_CRL_get_version returns the CRL version (1=v1, 2=v2).
func X509_CRL_get_version(crl unsafe.Pointer) int {
	return int(C.X509_CRL_get_version((*C.X509_CRL)(crl)))
}

// X509_CRL_get0_lastUpdate 返回 CRL 生效时间（unix 秒）。
//
// X509_CRL_get0_lastUpdate returns the CRL thisUpdate time (unix seconds).
func X509_CRL_get0_lastUpdate(crl unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_CRL_get0_lastUpdate((*C.X509_CRL)(crl)))
}

// X509_CRL_get0_nextUpdate 返回 CRL 过期时间（unix 秒）。
//
// X509_CRL_get0_nextUpdate returns the CRL nextUpdate time (unix seconds).
func X509_CRL_get0_nextUpdate(crl unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_CRL_get0_nextUpdate((*C.X509_CRL)(crl)))
}

// X509_CRL_get_issuer 返回 CRL 签发者名字（内部指针，勿释放）。
//
// X509_CRL_get_issuer returns the internal issuer name pointer of crl;
// do NOT free it.
func X509_CRL_get_issuer(crl unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_get_issuer((*C.X509_CRL)(crl)))
}

// X509_CRL_get_REVOKED 返回 CRL 吊销条目栈（内部指针，勿释放）。
//
// X509_CRL_get_REVOKED returns the internal revoked-entries stack; do NOT
// free it.
func X509_CRL_get_REVOKED(crl unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_get_REVOKED((*C.X509_CRL)(crl)))
}

// X509_CRL_get_signature_info 返回 CRL 签名的原始字节、签名算法 NID 与签名算法 OID（点分文本）。
// 任一字段不可用时返回空值（nil / 0 / ""），永不返回错误。
//
// X509_CRL_get_signature_info returns the raw signature bytes, the
// signature algorithm NID, and the signature algorithm OID as dotted
// text from crl. When a field is unavailable the corresponding zero
// value (nil / 0 / "") is returned; the call never reports an error.
func X509_CRL_get_signature_info(crl unsafe.Pointer) ([]byte, int, string) {
	var psig *C.ASN1_BIT_STRING
	var palg *C.X509_ALGOR
	C.X509_CRL_get0_signature((*C.X509_CRL)(crl), &psig, &palg)

	var sig []byte
	if psig != nil {
		length := C.ASN1_STRING_length((*C.ASN1_STRING)(psig))
		data := C.ASN1_STRING_get0_data((*C.ASN1_STRING)(psig))
		if length > 0 && data != nil {
			sig = C.GoBytes(unsafe.Pointer(data), C.int(length))
		}
	}

	var nid int
	var oid string
	if palg != nil {
		var paobj *C.ASN1_OBJECT
		var pptype C.int
		var ppval unsafe.Pointer
		C.X509_ALGOR_get0(&paobj, &pptype, &ppval, palg)
		if paobj != nil {
			nid = int(C.OBJ_obj2nid(paobj))
			n := C.OBJ_obj2txt(nil, 0, paobj, C.int(1))
			if n > 0 {
				buf := make([]C.char, n+1)
				C.OBJ_obj2txt(&buf[0], n+1, paobj, C.int(1))
				oid = C.GoString(&buf[0])
			}
		}
	}
	return sig, nid, oid
}

// X509_CRL_get_ext_count 返回 CRL 扩展数量。
//
// X509_CRL_get_ext_count returns the number of extensions on crl.
func X509_CRL_get_ext_count(crl unsafe.Pointer) int {
	return int(C.X509_CRL_get_ext_count((*C.X509_CRL)(crl)))
}

// X509_CRL_get_ext 返回 CRL 第 i 个扩展（内部指针，勿释放）。
//
// X509_CRL_get_ext returns the i-th extension of crl as an internal pointer; do NOT free it.
func X509_CRL_get_ext(crl unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_get_ext((*C.X509_CRL)(crl), C.int(i)))
}

// X509_CRL_get0_authority_key_id 返回 CRL 的 AKID keyid 字节。
// 通过 shim 函数 X_X509_CRL_get_akid_keyid 取出 AUTHORITY_KEYID.keyid 的内部指针，
// 返回 keyid 字节的副本；无 AKID 或无 keyid 时返回 nil。
//
// X509_CRL_get0_authority_key_id returns a copy of the AuthorityKeyIdentifier
// keyid bytes from crl, or nil when the AKID extension is absent or has
// no keyid component.
func X509_CRL_get0_authority_key_id(crl unsafe.Pointer) []byte {
	var length C.int
	c := C.X_X509_CRL_get_akid_keyid((*C.X509_CRL)(crl), &length)
	if c == nil || length <= 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(c), length)
}

// X509_CRL_get_crl_number 返回 CRL Number 扩展的 INTEGER（nil 表示无）。
// 调用方负责通过 ASN1_INTEGER_free 释放。
//
// X509_CRL_get_crl_number returns the CRL Number extension as an
// ASN1_INTEGER (nil when absent). The caller must release it with
// ASN1_INTEGER_free.
func X509_CRL_get_crl_number(crl unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.X509_CRL_get_ext_d2i((*C.X509_CRL)(crl),
		C.int(NidCrlNumber), nil, nil))
}

// NidCrlNumber 是 CRL Number 扩展 NID（来自 obj_mac.h：NID_crl_number = 88）。
//
// NidCrlNumber is the OpenSSL NID for the CRL Number extension
// (RFC 5280 §5.2.3: NID_crl_number = 88).
const NidCrlNumber = 88

// X509_sk_X509_REVOKED_num 返回吊销条目数。
//
// X509_sk_X509_REVOKED_num returns the number of revoked entries.
func X509_sk_X509_REVOKED_num(sk unsafe.Pointer) int {
	return int(C.X_sk_X509_REVOKED_num(sk))
}

// X509_sk_X509_REVOKED_value 返回第 i 个吊销条目（内部指针）。
//
// X509_sk_X509_REVOKED_value returns the i-th revoked entry as an internal
// pointer; do NOT free it.
func X509_sk_X509_REVOKED_value(sk unsafe.Pointer, i int) unsafe.Pointer {
	return unsafe.Pointer(C.X_sk_X509_REVOKED_value(sk, C.int(i)))
}

// X509_REVOKED_get0_serialNumber 返回吊销条目的序列号。
//
// X509_REVOKED_get0_serialNumber returns the serial number of rev as int64;
// returns 0 when the field is missing.
func X509_REVOKED_get0_serialNumber(rev unsafe.Pointer) int64 {
	ai := C.X509_REVOKED_get0_serialNumber((*C.X509_REVOKED)(rev))
	if ai == nil {
		return 0
	}
	return int64(C.ASN1_INTEGER_get(ai))
}

// X509_REVOKED_get0_revocationDate 返回吊销条目的吊销时间（unix 秒）。
//
// X509_REVOKED_get0_revocationDate returns the revocationDate of rev in
// unix seconds.
func X509_REVOKED_get0_revocationDate(rev unsafe.Pointer) int64 {
	return asn1TimeToUnix(C.X509_REVOKED_get0_revocationDate((*C.X509_REVOKED)(rev)))
}

// X509_REVOKED_crl_reason 返回吊销条目的原因码（无原因返回 -1）。
//
// X509_REVOKED_crl_reason returns the CRL Reason Code (0..10, e.g.
// keyCompromise=1, caCompromise=2) or -1 when no reason is set.
func X509_REVOKED_crl_reason(rev unsafe.Pointer) int {
	en := C.X509_REVOKED_get_ext_d2i((*C.X509_REVOKED)(rev), C.int(NidCrlReason), nil, nil)
	if en == nil {
		return -1
	}
	defer C.X_ASN1_ENUMERATED_free(en)
	return int(C.ASN1_ENUMERATED_get((*C.ASN1_ENUMERATED)(en)))
}
