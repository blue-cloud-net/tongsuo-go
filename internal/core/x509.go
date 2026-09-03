package core

import (
	"encoding/hex"
	"fmt"
	"time"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// NameEntry 表示 X.509 名字中的一个 RDN 条目。
//
// NameEntry is one RDN entry inside an X.509 Name.
type NameEntry struct {
	Nid   int    // 字段 NID（如 native.NidCommonName）
	Field string // 字段短名（如 "CN"、"O"）
	Value string // 字段值（UTF-8）
}

// Name 表示 X.509 名字（X509_NAME 的包装），用于构建证书主题/签发者。
//
// 类型通过内部 Handle 拥有底层 X509_NAME 句柄；调用完毕后须调用 Close 释放。
//
// Name is the Go wrapper around an OpenSSL X509_NAME and is used to build
// the subject and issuer of a certificate or CSR.
//
// The type owns the underlying X509_NAME handle through an internal Handle
// value; callers must invoke Close to release it once they are done with
// the Name.
type Name struct {
	handle *Handle
}

// NewName 创建空名字（不含任何 RDN 条目）。
//
// 返回值拥有底层 X509_NAME 句柄，调用方负责调用 Close 释放。
//
// NewName creates an empty Name with no RDN entries.
//
// The returned *Name owns the underlying X509_NAME handle and the caller
// is responsible for calling Close to release it.
func NewName() (*Name, error) {
	n := native.X509_NAME_new()
	if n == nil {
		return nil, NewOpError("x509: X509_NAME_new", native.PopError())
	}
	return &Name{handle: NewHandle(n, true, native.X509_NAME_free)}, nil
}

// AddEntry 向名字追加一条 RDN 条目。
//
// field 取 X509_NAME_add_entry_by_txt 支持的标准短名（"CN"/"C"/"O"/"OU"/"L"/"ST"/"serialNumber"/"emailAddress" 等）；Name 已通过 Close 关闭，或底层 OpenSSL 调用失败时返回错误（包装为 OpError）。
//
// AddEntry appends an RDN entry to the Name.
//
// The field argument accepts the standard short names "CN", "C", "O", "OU",
// "L", "ST", "serialNumber", "emailAddress", and similar identifiers
// understood by X509_NAME_add_entry_by_txt. The call returns an error
// when the Name has been closed via Close, or when the underlying
// OpenSSL call fails (wrapped as OpError).
func (n *Name) AddEntry(field, value string) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: name closed")
	}
	if !native.X509_NAME_add_entry_by_txt(n.handle.Ptr(), field, value) {
		return NewOpError("x509: X509_NAME_add_entry_by_txt", native.PopError())
	}
	return nil
}

// Text 返回名字中匹配指定 NID 的首条 RDN 文本（如 native.NidCommonName）。
//
// 对 nil 接收者或已关闭的 Name 调用是安全的：均返回空字符串。
//
// Text returns the textual value of the first RDN entry matching the
// given NID (for example native.NidCommonName).
//
// The method is safe to call on a nil receiver or on a closed Name: in
// both cases it returns the empty string.
func (n *Name) Text(nid int) string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	return native.X509_NAME_get_text_by_NID(n.handle.Ptr(), nid)
}

// Get 返回名字中匹配指定短名（如 "CN"、"O"）的首条 RDN 文本。
//
// 对 nil 接收者或已关闭的 Name 调用是安全的：均返回空字符串；短名未找到同样返回空字符串。
//
// Get returns the textual value of the first RDN entry matching the
// given short name (for example "CN" or "O").
//
// The method is safe to call on a nil receiver or on a closed Name: in
// both cases it returns the empty string. When the short name is not
// found in the Name the result is the empty string as well.
func (n *Name) Get(field string) string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	return native.X509_NAME_get_text_by_txt(n.handle.Ptr(), field)
}

// Nid 返回指定字段短名（如 "CN"、"O"）对应的 OpenSSL NID。
// field 可为短名 / 长名 / 点分 OID；未知字段返回 native.NidUndef（0）。
//
// 对 nil 接收者或已关闭的 Name 调用是安全的：均返回 native.NidUndef。
//
// Nid returns the OpenSSL NID for the given field name (short name, long
// name, or dotted OID), or native.NidUndef (0) when the field is
// unknown.
//
// The method is safe to call on a nil receiver or on a closed Name: in
// both cases it returns native.NidUndef.
func (n *Name) Nid(field string) int {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return native.NidUndef
	}
	return native.OBJ_txt2nid(field)
}

// Len 返回 Name 中的 RDN 条目数。
//
// 对 nil 接收者或已关闭的 Name 调用是安全的：均返回 0。
//
// Len returns the number of RDN entries in the Name.
//
// The method is safe to call on a nil receiver or on a closed Name: in
// both cases it returns 0.
func (n *Name) Len() int {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return 0
	}
	return native.X509_NAME_get_entry_count(n.handle.Ptr())
}

// Entries 按证书中的原始顺序返回名字的全部 RDN 条目。
//
// 对 nil 接收者或已关闭的 Name 调用是安全的：均返回 nil；解码失败的条目会被跳过而非中断遍历。
//
// Entries returns every RDN entry of the Name in their original order.
//
// The method is safe to call on a nil receiver or on a closed Name: in
// both cases it returns nil. Entries that fail to decode are omitted from
// the result rather than aborting the iteration.
func (n *Name) Entries() []NameEntry {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return nil
	}
	count := native.X509_NAME_get_entry_count(n.handle.Ptr())
	entries := make([]NameEntry, 0, count)
	for i := 0; i < count; i++ {
		e := native.X509_NAME_get_entry(n.handle.Ptr(), i)
		if e == nil {
			continue
		}
		nid := native.X509_NAME_ENTRY_nid(e)
		value, ok := native.X509_NAME_ENTRY_value(e)
		if !ok {
			continue
		}
		entries = append(entries, NameEntry{
			Nid:   nid,
			Field: native.OBJ_nid2sn(nid),
			Value: value,
		})
	}
	return entries
}

// String 返回名字的 OpenSSL 单行表示（如 "/CN=example.com/O=Example Org"）。
//
// 对 nil 接收者或已关闭的 Name 调用是安全的：均返回空字符串。
//
// String returns the OpenSSL one-line representation of the Name
// (for example "/CN=example.com/O=Example Org").
//
// The method is safe to call on a nil receiver or on a closed Name: in
// both cases it returns the empty string.
func (n *Name) String() string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	s, _ := native.X509_NAME_oneline(n.handle.Ptr())
	return s
}

// Close 释放底层 X509_NAME 句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的 Name 调用返回 nil，不产生副作用；Close 返回后，
// 其他方法对该 *Name 调用将返回 "x509: name closed" 错误（查询类方法返回空字符串/nil），
// 调用方须保证无并发 goroutine 仍持有该 Name 的引用。
//
// Close releases the underlying X509_NAME handle.
//
// The call is idempotent: invoking it on a nil receiver or on a Name
// that has already been closed returns nil without further side effects.
// After Close returns, any other method on the same *Name returns the
// error "x509: name closed" (or an empty string / nil for query-style
// methods), so the caller must guarantee that no concurrent goroutine
// still holds a reference to this Name.
func (n *Name) Close() error {
	if n == nil {
		return nil
	}
	return n.handle.Close()
}

// Certificate 表示一张 X.509 证书（X509 的包装）。
//
// 类型通过内部 Handle 拥有底层 X509 句柄；调用完毕后须调用 Close 释放。
//
// Certificate is the Go wrapper around an OpenSSL X509 certificate.
//
// The type owns the underlying X509 handle through an internal Handle
// value; callers must invoke Close to release the certificate once they
// are done with it.
type Certificate struct {
	handle *Handle
}

// NewCertificate 创建一张空证书（字段取默认值）。
//
// 返回值拥有底层 X509 句柄，调用方负责调用 Close 释放；新建对象须填充
// version/serial/subject/issuer/公钥/有效期/扩展等字段后调用 Sign 签名。
//
// NewCertificate creates an empty *Certificate with default fields.
//
// The returned certificate owns the underlying X509 handle and the
// caller is responsible for calling Close to release it. The freshly
// created object must be filled in (version, serial, subject, issuer,
// public key, validity, extensions, ...) and then signed with Sign.
func NewCertificate() (*Certificate, error) {
	x := native.X509_new()
	if x == nil {
		return nil, NewOpError("x509: X509_new", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// LoadCertificatePEM 解析 PEM 编码的 X.509 证书（"-----BEGIN CERTIFICATE-----"）。
//
// 输入为多证书 bundle 时仅返回第一张，其余字节被静默忽略；返回值拥有底层 X509
// 句柄，调用方须调用 Close 释放；错误以 OpError 包装。
//
// LoadCertificatePEM parses a PEM-encoded X.509 certificate
// ("-----BEGIN CERTIFICATE-----").
//
// When the input contains a bundle of certificates, only the first one
// is returned; the remaining bytes are silently ignored. The returned
// *Certificate owns the underlying X509 handle and the caller must
// invoke Close to release it. Errors are wrapped as OpError.
func LoadCertificatePEM(pem []byte) (*Certificate, error) {
	bio := native.BIO_new_mem_buf(pem)
	if bio == nil {
		return nil, NewOpError("x509: BIO_new_mem_buf", native.PopError())
	}
	defer native.BIO_free(bio)
	x := native.X_PEM_read_bio_X509(bio)
	if x == nil {
		return nil, NewOpError("x509: PEM_read_bio_X509", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// LoadCertificateDER 解析 ASN.1 DER 编码的 X.509 证书。
//
// 返回值拥有底层 X509 句柄，调用方须调用 Close 释放；错误以 OpError 包装。
//
// LoadCertificateDER parses an ASN.1 DER-encoded X.509 certificate.
//
// The returned *Certificate owns the underlying X509 handle and the
// caller must invoke Close to release it. Errors are wrapped as OpError.
func LoadCertificateDER(der []byte) (*Certificate, error) {
	x := native.D2i_X509(der)
	if x == nil {
		return nil, NewOpError("x509: d2i_X509", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// MarshalPEM 将证书序列化为 PEM 编码（"-----BEGIN CERTIFICATE-----"）。
//
// 证书已通过 Close 关闭，或底层 PEM_write_bio_X509 调用失败时返回错误（以 OpError 包装）。
//
// MarshalPEM serializes the certificate to its PEM encoding
// ("-----BEGIN CERTIFICATE-----").
//
// Returns an error if the certificate has been closed via Close, or if
// the underlying PEM_write_bio_X509 call fails (errors are wrapped as
// OpError).
func (c *Certificate) MarshalPEM() ([]byte, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: certificate closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_PEM_write_bio_X509(bio, c.handle.Ptr()) {
		return nil, NewOpError("x509: PEM_write_bio_X509", native.PopError())
	}
	return readAllBIO(bio)
}

// SetVersion 设置证书的 X.509 版本（0=v1，2=v3）。
//
// 约定与 OpenSSL X509_set_version 一致：0 表示 v1、2 表示 v3；须在 Sign 之前调用。
//
// SetVersion sets the X.509 version of the certificate (0 for v1, 2 for v3).
//
// The convention matches OpenSSL's X509_set_version: 0 means v1 and 2
// means v3. Must be invoked before Sign.
func (c *Certificate) SetVersion(version int) error {
	if !native.X509_set_version(c.handle.Ptr(), version) {
		return NewOpError("x509: X509_set_version", native.PopError())
	}
	return nil
}

// SetSerial 设置证书序列号。
//
// 须在 Sign 之前调用；底层 OpenSSL 调用错误以 OpError 包装。
//
// SetSerial sets the certificate serial number.
//
// Must be invoked before Sign. Errors from the underlying OpenSSL call
// are wrapped as OpError.
func (c *Certificate) SetSerial(serial int64) error {
	if !native.X509_set_serial_int(c.handle.Ptr(), serial) {
		return NewOpError("x509: X509_set_serialNumber", native.PopError())
	}
	return nil
}

// SetIssuer 设置证书的签发者名字。
//
// 参数 n 必须是未关闭的有效 Name；否则返回 "x509: invalid issuer name" 错误；底层 OpenSSL 调用错误以 OpError 包装。
//
// SetIssuer sets the issuer Name of the certificate.
//
// The argument n must be a live, non-closed Name; otherwise the call
// returns the error "x509: invalid issuer name". Errors from the
// underlying OpenSSL call are wrapped as OpError.
func (c *Certificate) SetIssuer(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid issuer name")
	}
	if !native.X509_set_issuer_name(c.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_set_issuer_name", native.PopError())
	}
	return nil
}

// SetSubject 设置证书的主题名字。
//
// 参数 n 必须是未关闭的有效 Name；否则返回 "x509: invalid subject name" 错误；底层 OpenSSL 调用错误以 OpError 包装。
//
// SetSubject sets the subject Name of the certificate.
//
// The argument n must be a live, non-closed Name; otherwise the call
// returns the error "x509: invalid subject name". Errors from the
// underlying OpenSSL call are wrapped as OpError.
func (c *Certificate) SetSubject(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid subject name")
	}
	if !native.X509_set_subject_name(c.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_set_subject_name", native.PopError())
	}
	return nil
}

// SetPublicKey 关联证书的公钥。
//
// 参数 k 必须是未关闭的有效 PKey；否则返回 "x509: invalid public key" 错误；底层 OpenSSL 调用错误以 OpError 包装。
//
// SetPublicKey associates the certificate with the given *PKey.
//
// The argument k must be a live, non-closed PKey; otherwise the call
// returns the error "x509: invalid public key". Errors from the
// underlying OpenSSL call are wrapped as OpError.
func (c *Certificate) SetPublicKey(k *PKey) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_set_pubkey(c.handle.Ptr(), k.handle.Ptr()) {
		return NewOpError("x509: X509_set_pubkey", native.PopError())
	}
	return nil
}

// SetValidity 设置证书的有效期。
//
// 参数为绝对 time.Time；notAfter 必须严格大于 notBefore，否则返回 "x509: notAfter must be after notBefore" 错误（不调用 OpenSSL）；ASN1_TIME_set 错误以 OpError 包装。
//
// SetValidity sets the validity period of the certificate.
//
// The arguments are expressed as absolute time.Time values; notAfter
// must be strictly greater than notBefore or the call returns the error
// "x509: notAfter must be after notBefore" without invoking OpenSSL.
// Errors from ASN1_TIME_set are wrapped as OpError.
func (c *Certificate) SetValidity(notBefore, notAfter time.Time) error {
	if !notAfter.After(notBefore) {
		return fmt.Errorf("x509: notAfter must be after notBefore")
	}
	if !native.X509_set_not_before(c.handle.Ptr(), notBefore.Unix()) {
		return NewOpError("x509: ASN1_TIME_set(notBefore)", native.PopError())
	}
	if !native.X509_set_not_after(c.handle.Ptr(), notAfter.Unix()) {
		return NewOpError("x509: ASN1_TIME_set(notAfter)", native.PopError())
	}
	return nil
}

// AddBasicConstraints 添加 BasicConstraints 扩展。
//
// isCA 为 true 时标记为 critical,CA:TRUE，否则标记为 critical,CA:FALSE；须在 Sign 之前调用；底层 OpenSSL 调用错误以 OpError 包装。
//
// AddBasicConstraints adds a BasicConstraints extension to the certificate.
//
// Must be invoked before Sign. When isCA is true the extension is marked
// as critical with CA:TRUE; otherwise it is marked as critical with
// CA:FALSE. Errors from the underlying OpenSSL call are wrapped as
// OpError.
func (c *Certificate) AddBasicConstraints(isCA bool) error {
	val := "critical,CA:FALSE"
	if isCA {
		val = "critical,CA:TRUE"
	}
	ext := native.X509V3_EXT_conf_nid(native.NidBasicConstraints, val)
	if ext == nil {
		return NewOpError("x509: X509V3_EXT_conf_nid(basicConstraints)", native.PopError())
	}
	defer native.X509_EXTENSION_free(ext)
	if !native.X509_add_ext(c.handle.Ptr(), ext) {
		return NewOpError("x509: X509_add_ext", native.PopError())
	}
	return nil
}

// Sign 使用签名私钥对证书签名。
//
// 自签时签名密钥与公钥对应，CA 签发时使用 CA 私钥；md 传 nil 时按签名密钥类型自动选择（SM2→SM3，RSA/ECDSA→SHA256）；signer 必须是未关闭的有效 PKey；底层 X509_sign 调用错误以 OpError 包装。
//
// Sign signs the certificate with the given signing key.
//
// signer must be a live, non-closed PKey. For self-signed certificates the
// signing key matches the certificate's public key; for CA-issued
// certificates the signing key is the CA's private key. When md is nil
// the digest is selected automatically by signer type (SM2→SM3,
// RSA/ECDSA→SHA256). Errors from the underlying X509_sign call are
// wrapped as OpError.
func (c *Certificate) Sign(signer *PKey, md *Digest) error {
	if signer == nil || signer.handle == nil || signer.handle.IsClosed() {
		return fmt.Errorf("x509: invalid signer")
	}
	if md == nil {
		md = digestForSigner(signer)
	}
	if md == nil || md.handle == nil {
		return fmt.Errorf("x509: invalid digest")
	}
	if !native.X509_sign(c.handle.Ptr(), signer.handle.Ptr(), md.handle.Ptr()) {
		return NewOpError("x509: X509_sign", native.PopError())
	}
	return nil
}

// Verify 使用公钥验证证书签名。
//
// pub 必须是未关闭的有效 PKey；该调用仅校验密码学签名，完整路径验证
// （BasicConstraints、KeyUsage、有效期、CRL 等）请使用 ChainVerify；底层 X509_verify 错误以 OpError 包装。
//
// Verify checks the certificate signature against the given public key.
//
// pub must be a live, non-closed PKey. The call only verifies the
// cryptographic signature; use ChainVerify for full path validation
// (including BasicConstraints, key usage, validity period, and CRL
// checks). Errors from the underlying X509_verify call are wrapped as
// OpError.
func (c *Certificate) Verify(pub *PKey) error {
	if pub == nil || pub.handle == nil || pub.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_verify(c.handle.Ptr(), pub.handle.Ptr()) {
		return NewOpError("x509: X509_verify", native.PopError())
	}
	return nil
}

// Signature 返回证书的原始签名字节（ASN.1 BIT STRING 内容，DER 编码）。
//
// 对 nil 或已关闭证书返回 nil；不可用时同样返回 nil，不返回错误。
//
// Signature returns the raw signature bytes of the certificate (the
// contents of the ASN.1 BIT STRING, i.e. the DER-encoded signature).
//
// The result is nil for a nil or closed certificate, and also nil when
// the signature is unavailable; the call never reports an error.
func (c *Certificate) Signature() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	sig, _, _ := native.X509_get_signature_info(c.handle.Ptr())
	return sig
}

// SignatureAlgorithm 返回证书签名算法的短名（如 "SM2-SM3"、"RSA-SHA256"、"ecdsa-with-SHA256"）。
//
// 对 nil 或已关闭证书返回空字符串；OpenSSL 无法识别签名算法时同样返回空字符串。返回值取自 OBJ_nid2_sn。
//
// SignatureAlgorithm returns the certificate signature algorithm short name
// (for example "SM2-SM3", "RSA-SHA256", or "ecdsa-with-SHA256").
//
// The result is the empty string for a nil or closed certificate, and
// also when the signature algorithm is not recognized by OpenSSL. The
// value comes from OBJ_nid2_sn.
func (c *Certificate) SignatureAlgorithm() string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return ""
	}
	_, nid, _ := native.X509_get_signature_info(c.handle.Ptr())
	return native.OBJ_nid2sn(nid)
}

// SignatureAlgorithmOID 返回证书签名算法的 OID 点分文本（如 "1.2.156.10197.1.501"、"1.2.840.113549.1.1.11"）。
//
// 对 nil 或已关闭证书返回空字符串；OpenSSL 无法读取算法 OID 时同样返回空字符串。返回值取自 OBJ_obj2txt(_, _, _, 1)。
//
// SignatureAlgorithmOID returns the certificate signature algorithm OID
// as a dotted string (for example "1.2.156.10197.1.501" for SM2-with-SM3
// or "1.2.840.113549.1.1.11" for sha256WithRSAEncryption).
//
// The result is the empty string for a nil or closed certificate, and
// also when the signature algorithm OID cannot be read. The value comes
// from OBJ_obj2txt(_, _, _, 1).
func (c *Certificate) SignatureAlgorithmOID() string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return ""
	}
	_, _, oid := native.X509_get_signature_info(c.handle.Ptr())
	return oid
}

// SubjectName 返回证书主题名字。
//
// 返回的 *Name 包装了底层 X509 借用的内部 X509_NAME 指针；调用方不得对其调用 Close，指针在证书生命周期内有效。
//
// SubjectName returns the subject Name of the certificate.
//
// The returned *Name wraps an internal X509_NAME pointer borrowed from
// the underlying X509; the caller must NOT call Close on it. The pointer
// remains valid for the lifetime of the certificate.
func (c *Certificate) SubjectName() *Name {
	n := native.X509_get_subject_name(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// IssuerName 返回证书签发者名字。
//
// 返回的 *Name 包装了底层 X509 借用的内部 X509_NAME 指针；调用方不得对其调用 Close，指针在证书生命周期内有效。
//
// IssuerName returns the issuer Name of the certificate.
//
// The returned *Name wraps an internal X509_NAME pointer borrowed from
// the underlying X509; the caller must NOT call Close on it. The pointer
// remains valid for the lifetime of the certificate.
func (c *Certificate) IssuerName() *Name {
	n := native.X509_get_issuer_name(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// Subject 返回主题的 CN（Common Name）。
//
// Subject returns the Common Name (NID_commonName) of the certificate
// subject. Returns the empty string when the subject has no CN.
func (c *Certificate) Subject() string {
	n := c.SubjectName()
	if n == nil {
		return ""
	}
	return n.Text(native.NidCommonName)
}

// Issuer 返回签发者的 CN（Common Name）。
//
// Issuer returns the Common Name (NID_commonName) of the certificate
// issuer. Returns the empty string when the issuer has no CN.
func (c *Certificate) Issuer() string {
	n := c.IssuerName()
	if n == nil {
		return ""
	}
	return n.Text(native.NidCommonName)
}

// NotBefore 返回生效时间。
//
// NotBefore returns the certificate "not before" validity time in UTC.
func (c *Certificate) NotBefore() time.Time {
	return time.Unix(native.X509_get_not_before(c.handle.Ptr()), 0).UTC()
}

// NotAfter 返回过期时间。
//
// NotAfter returns the certificate "not after" validity time in UTC.
func (c *Certificate) NotAfter() time.Time {
	return time.Unix(native.X509_get_not_after(c.handle.Ptr()), 0).UTC()
}

// Serial 返回证书序列号。
//
// Serial returns the certificate serial number as a signed 64-bit integer.
func (c *Certificate) Serial() int64 {
	return native.X509_get_serial_int(c.handle.Ptr())
}

// Version 返回证书的 X.509 版本：0=v1，1=v2，2=v3。
//
// 对 nil 接收者或已关闭的证书调用返回 0。
//
// Version returns the X.509 version of the certificate: 0 for v1,
// 1 for v2, and 2 for v3.
//
// Returns 0 when called on a nil receiver or on a closed certificate.
func (c *Certificate) Version() int {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return 0
	}
	return native.X509_get_version(c.handle.Ptr())
}

// SubjectEntries 返回主题完整 RDN 条目。
//
// SubjectEntries returns the full RDN entry list of the certificate
// subject. Returns nil when the subject name is unavailable.
func (c *Certificate) SubjectEntries() []NameEntry {
	n := c.SubjectName()
	if n == nil {
		return nil
	}
	return n.Entries()
}

// IssuerEntries 返回签发者完整 RDN 条目。
//
// IssuerEntries returns the full RDN entry list of the certificate
// issuer. Returns nil when the issuer name is unavailable.
func (c *Certificate) IssuerEntries() []NameEntry {
	n := c.IssuerName()
	if n == nil {
		return nil
	}
	return n.Entries()
}

// SubjectText 返回主题完整 RDN 单行文本。
//
// SubjectText returns the OpenSSL one-line representation of the
// certificate subject (for example "/CN=example.com/O=Example Org").
// Returns the empty string when the subject name is unavailable.
func (c *Certificate) SubjectText() string {
	n := c.SubjectName()
	if n == nil {
		return ""
	}
	return n.String()
}

// IssuerText 返回签发者完整 RDN 单行文本。
//
// IssuerText returns the OpenSSL one-line representation of the
// certificate issuer. Returns the empty string when the issuer name
// is unavailable.
func (c *Certificate) IssuerText() string {
	n := c.IssuerName()
	if n == nil {
		return ""
	}
	return n.String()
}

// SAN 返回证书 subjectAltName 扩展条目切片（如 "DNS:example.com"、"IP:1.2.3.4"）。
//
// 每条以 `openssl x509 -text` 风格加前缀（"email:"/"DNS:"/"URI:"/"IP:"/"RID:"/"dirName:"/"ediPartyName:"）；证书已关闭或无 SAN 扩展时返回 nil。
//
// SAN returns the certificate's subjectAltName extension entries as a
// slice of strings (for example "DNS:example.com" or "IP:1.2.3.4").
//
// Each entry is prefixed to mirror the `openssl x509 -text` output style
// ("email:" / "DNS:" / "URI:" / "IP:" / "RID:" / "dirName:" /
// "ediPartyName:"). The method returns nil when the certificate has
// been closed or has no SAN extension.
func (c *Certificate) SAN() []string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	names := native.X509_get_san(c.handle.Ptr())
	if names == nil {
		return nil
	}
	defer native.X509_GENERAL_NAMES_free(names)
	count := native.X509_GENERAL_NAMES_num(names)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		gn := native.X509_GENERAL_NAMES_value(names, i)
		if gn == nil {
			continue
		}
		t := native.X509_GENERAL_NAME_type(gn)
		v := native.X509_GENERAL_NAME_to_string(gn)
		out = append(out, formatGeneralName(t, v))
	}
	return out
}

// formatGeneralName 按类型给 SAN 值加前缀（与 openssl 输出风格一致）。
//
// formatGeneralName prefixes v with the OpenSSL-style type tag
// ("email:", "DNS:", "URI:", "IP:" or "DirName:") matching the GeneralName
// type t. Unknown types are returned unchanged.
func formatGeneralName(t int, v string) string {
	switch t {
	case native.GenEmail:
		return "email:" + v
	case native.GenDNS:
		return "DNS:" + v
	case native.GenURI:
		return "URI:" + v
	case native.GenIPAdd:
		return "IP:" + v
	case native.GenRegistered:
		return "RID:" + v
	case native.GenDirName:
		return "dirName:" + v
	case native.GenEdiParty:
		return "ediPartyName:" + v
	default:
		return v
	}
}

// keyUsageNames 将 RFC 5280 KeyUsage 位（0–8）映射为可读名称。
//
// keyUsageNames maps the RFC 5280 KeyUsage bit positions (0–8) to their
// ASN.1 names, used by MarshalPEM / textual dumps to mirror the
// `openssl x509 -text` output.
var keyUsageNames = map[int]string{
	0: "digitalSignature",
	1: "nonRepudiation",
	2: "keyEncipherment",
	3: "dataEncipherment",
	4: "keyAgreement",
	5: "keyCertSign",
	6: "cRLSign",
	7: "encipherOnly",
	8: "decipherOnly",
}

// KeyUsage 返回证书 KeyUsage 扩展已置位的能力位名称列表（如 ["digitalSignature"]）。
//
// 证书已关闭或无 KeyUsage 扩展时返回 nil；位名称遵循 RFC 5280
// （"digitalSignature"、"nonRepudiation"、"keyEncipherment"、"dataEncipherment"、
// "keyAgreement"、"keyCertSign"、"cRLSign"、"encipherOnly"、"decipherOnly"）。
//
// KeyUsage returns the list of capability names set in the certificate's
// KeyUsage extension (for example ["digitalSignature"]).
//
// Returns nil when the certificate has been closed or has no KeyUsage
// extension. The bit names follow RFC 5280
// ("digitalSignature", "nonRepudiation", "keyEncipherment",
// "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
// "encipherOnly", "decipherOnly").
func (c *Certificate) KeyUsage() []string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	bs := native.X509_get_key_usage(c.handle.Ptr())
	if bs == nil {
		return nil
	}
	defer native.X509_ASN1_BIT_STRING_free(bs)
	var out []string
	for bit := 0; bit <= 8; bit++ {
		if native.ASN1_BIT_STRING_get_bit(bs, bit) {
			out = append(out, keyUsageNames[bit])
		}
	}
	return out
}

// ExtendedKeyUsage 返回证书 extendedKeyUsage 扩展声明的用途 OID 长名列表（如 ["serverAuth"]）。
//
// 证书已关闭或无 EKU 扩展时返回 nil；每条由 OBJ_to_string 生成对应的 OID 长名。
//
// ExtendedKeyUsage returns the list of purpose OIDs declared in the
// certificate's extendedKeyUsage extension (for example ["serverAuth"]).
//
// Returns nil when the certificate has been closed or has no EKU
// extension. Each entry is the long name of the corresponding purpose
// OID, as produced by OBJ_to_string.
func (c *Certificate) ExtendedKeyUsage() []string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	eku := native.X509_get_eku(c.handle.Ptr())
	if eku == nil {
		return nil
	}
	defer native.X509_EXTENDED_KEY_USAGE_free(eku)
	count := native.X509_EXTENDED_KEY_USAGE_num(eku)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		o := native.X509_EXTENDED_KEY_USAGE_value(eku, i)
		if o == nil {
			continue
		}
		out = append(out, native.OBJ_to_string(o))
	}
	return out
}

// IsCA 报告证书是否为 CA（BasicConstraints 的 CA 标志为真）。
//
// IsCA reports whether the certificate has the BasicConstraints CA flag
// set. Returns false for nil receivers and closed certificates.
func (c *Certificate) IsCA() bool {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return false
	}
	bc := native.X509_get_basic_constraints(c.handle.Ptr())
	if bc == nil {
		return false
	}
	defer native.X509_BASIC_CONSTRAINTS_free(bc)
	return native.X509_BASIC_CONSTRAINTS_ca(bc) != 0
}

// PathLen 返回 BasicConstraints 扩展中的 CA 路径长度约束。
//
// 证书已关闭、无 BasicConstraints 扩展或扩展省略 pathlen 约束（表示"无限制"）时返回 -1。
//
// PathLen returns the CA path-length constraint from the
// BasicConstraints extension.
//
// Returns -1 when the certificate has been closed, when no
// BasicConstraints extension is present, or when the extension omits the
// pathlen constraint (which means "no limit").
func (c *Certificate) PathLen() int64 {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return -1
	}
	bc := native.X509_get_basic_constraints(c.handle.Ptr())
	if bc == nil {
		return -1
	}
	defer native.X509_BASIC_CONSTRAINTS_free(bc)
	return native.X509_BASIC_CONSTRAINTS_pathlen(bc)
}

// SubjectKeyID 返回 subjectKeyIdentifier 扩展字节；无则返回 nil。
//
// SubjectKeyID returns the raw bytes of the subjectKeyIdentifier
// extension. Returns nil when the certificate has been closed or has
// no SKID extension.
func (c *Certificate) SubjectKeyID() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	return native.X509_get0_subject_key_id(c.handle.Ptr())
}

// AuthorityKeyID 返回 authorityKeyIdentifier 扩展中 keyid 的字节；无则返回 nil。
//
// AuthorityKeyID returns the keyid bytes of the authorityKeyIdentifier
// extension. Returns nil when the certificate has been closed or has
// no AKID extension.
func (c *Certificate) AuthorityKeyID() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	return native.X509_get0_authority_key_id(c.handle.Ptr())
}

// CertificateType 返回证书公钥算法名（如 "SM2"、"RSA"、"EC"）。
//
// CertificateType returns the algorithm name of the certificate's public
// key (for example "SM2", "RSA", or "EC"). Returns the empty string
// when the public key cannot be read; the temporary *PKey that is
// allocated internally is always released.
func (c *Certificate) CertificateType() string {
	k, err := c.PublicKey()
	if err != nil {
		return ""
	}
	defer k.Close()
	return k.Algorithm()
}

// Fingerprint 计算证书指纹并以小写十六进制字符串返回。
//
// 传入 core.SHA1()/core.SHA256() 等任意有效 *Digest 作为 md 选择摘要算法；证书已关闭、md 为 nil 或已关闭、或底层 X509_digest 调用失败时返回错误（包装为 OpError）。
//
// Fingerprint computes the certificate fingerprint and returns it as a
// lowercase hexadecimal string.
//
// Pass core.SHA1() or core.SHA256() (or any other live *Digest) as md to
// select the digest algorithm. Returns an error when the certificate has
// been closed, when md is nil or closed, or when the underlying
// X509_digest call fails (wrapped as OpError).
func (c *Certificate) Fingerprint(md *Digest) (string, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return "", fmt.Errorf("x509: certificate closed")
	}
	if md == nil || md.handle == nil {
		return "", fmt.Errorf("x509: invalid digest")
	}
	fp, ok := native.X509_digest(c.handle.Ptr(), md.handle.Ptr())
	if !ok {
		return "", NewOpError("x509: X509_digest", native.PopError())
	}
	return hex.EncodeToString(fp), nil
}

// Extension 表示证书/CSR 中的一个 X.509 扩展。
//
// 从证书/CSR 读取扩展时填充 Nid/Field/Critical/Data；通过 AddExtension 编程构造时使用 Nid 和 Value，
// Value 为 X509V3_EXT_conf 配置串（如 "DNS:example.com"，可带 "critical," 前缀）。
//
// Extension is one X.509 extension in a certificate or CSR.
//
// When the extension is read from a certificate or CSR, Nid, Field,
// Critical and Data are populated. When the extension is built
// programmatically and added via AddExtension, Nid and Value are used:
// Value is the X509V3_EXT_conf configuration string (for example
// "DNS:example.com", optionally with a "critical," prefix).
type Extension struct {
	Nid      int    // 扩展 NID（如 native.NidSubjectAltName）
	Field    string // 扩展短名（读取时填充，如 "subjectAltName"）
	Critical bool   // critical 标志（读取时填充）
	Value    string // X509V3_EXT_conf 配置串（构建时使用，如 "DNS:example.com"）
	Data     []byte // DER 编码的扩展值（读取时填充）
}

// Extensions 按出现顺序返回证书的全部扩展。
//
// 对 nil 或已关闭的证书返回 nil；每条包含扩展 NID、短名、critical 标志及 DER 字节。
//
// Extensions returns every extension of the certificate in their original
// order.
//
// The result is nil for a nil or closed certificate. Each entry contains
// the extension NID, short name, critical flag and DER bytes.
func (c *Certificate) Extensions() []Extension {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	count := native.X509_get_ext_count(c.handle.Ptr())
	out := make([]Extension, 0, count)
	for i := 0; i < count; i++ {
		e := native.X509_get_ext(c.handle.Ptr(), i)
		if e == nil {
			continue
		}
		nid := native.OBJ_obj2nid(native.X509_EXTENSION_get_object(e))
		out = append(out, Extension{
			Nid:      nid,
			Field:    native.OBJ_nid2sn(nid),
			Critical: native.X509_EXTENSION_get_critical(e) != 0,
			Data:     native.ASN1_STRING_data_bytes(native.X509_EXTENSION_get_data(e)),
		})
	}
	return out
}

// AddExtension 向证书追加通用扩展。
//
// nid 为扩展 NID（如 native.NidSubjectAltName）；value 为 X509V3_EXT_conf 配置串（如 "DNS:example.com"），可带 "critical," 前缀以标记为 critical；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddExtension appends a generic extension to the certificate.
//
// Must be invoked before Sign. nid is the extension NID (for example
// native.NidSubjectAltName); value is the X509V3_EXT_conf configuration
// string, e.g. "DNS:example.com", optionally prefixed with "critical,"
// to mark the extension critical. Errors from the underlying OpenSSL
// call are wrapped as OpError.
func (c *Certificate) AddExtension(nid int, value string) error {
	return c.addExtCtx(c, nil, nid, value)
}

// AddSubjectAltName 向证书追加 subjectAltName 扩展。
//
// value 为 OpenSSL 逗号分隔的 SAN 列表（如 "DNS:example.com,IP:1.2.3.4"）；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddSubjectAltName appends a subjectAltName extension to the certificate.
//
// value is the OpenSSL comma-separated SAN list (for example
// "DNS:example.com,IP:1.2.3.4"). Must be invoked before Sign. Errors
// from the underlying OpenSSL call are wrapped as OpError.
func (c *Certificate) AddSubjectAltName(value string) error {
	return c.AddExtension(native.NidSubjectAltName, value)
}

// AddKeyUsage 向证书追加 KeyUsage 扩展。
//
// value 为 OpenSSL 逗号分隔的能力位列表（如 "critical,digitalSignature,keyEncipherment"）；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddKeyUsage appends a KeyUsage extension to the certificate.
//
// value is the OpenSSL comma-separated capability list (for example
// "critical,digitalSignature,keyEncipherment"). Must be invoked before
// Sign. Errors from the underlying OpenSSL call are wrapped as OpError.
func (c *Certificate) AddKeyUsage(value string) error {
	return c.AddExtension(native.NidKeyUsage, value)
}

// AddExtendedKeyUsage 向证书追加 extendedKeyUsage 扩展。
//
// value 为 OpenSSL 逗号分隔的用途列表（如 "serverAuth,clientAuth"）；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddExtendedKeyUsage appends an extendedKeyUsage extension to the
// certificate.
//
// value is the OpenSSL comma-separated purpose list (for example
// "serverAuth,clientAuth"). Must be invoked before Sign. Errors from
// the underlying OpenSSL call are wrapped as OpError.
func (c *Certificate) AddExtendedKeyUsage(value string) error {
	return c.AddExtension(native.NidExtKeyUsage, value)
}

// AddSubjectKeyID 追加 subjectKeyIdentifier 扩展。
//
// 扩展值取 "hash"——按主题公钥的 SHA-1 哈希计算；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddSubjectKeyID appends a subjectKeyIdentifier extension computed from
// the SHA-1 hash of the subject's public key value.
//
// Must be invoked before Sign. Errors from the underlying OpenSSL call
// are wrapped as OpError.
func (c *Certificate) AddSubjectKeyID() error {
	return c.addExtCtx(c, nil, native.NidSubjectKeyIdentifier, "hash")
}

// AddAuthorityKeyID 追加 authorityKeyIdentifier 扩展。
//
// keyid 优先取自 issuer 证书的 SKID，否则按 issuer 公钥计算；issuer 必须是已设置公钥（建议调用 AddSubjectKeyID）的未关闭 *Certificate；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddAuthorityKeyID appends an authorityKeyIdentifier extension whose
// keyid is taken from the issuer certificate's SKID (preferred) or
// computed from the issuer's public key.
//
// issuer must be a live, non-closed *Certificate and must have had its
// public key set (AddSubjectKeyID is recommended). Must be invoked
// before Sign. Errors from the underlying OpenSSL call are wrapped as
// OpError.
func (c *Certificate) AddAuthorityKeyID(issuer *Certificate) error {
	if issuer == nil || issuer.handle == nil || issuer.handle.IsClosed() {
		return fmt.Errorf("x509: invalid issuer certificate")
	}
	return c.addExtCtx(c, issuer, native.NidAuthorityKeyIdentifier, "keyid:always")
}

// addExtCtx 带 X509V3_CTX 创建扩展并追加（subject 用于 SKID，issuer 用于 AKID）。
//
// addExtCtx creates an X509V3 extension with the supplied X509V3_CTX
// (subject supplies the SKID context, issuer supplies the AKID context)
// and appends it to c. Returns an error wrapping an OpError on failure.
func (c *Certificate) addExtCtx(subject, issuer *Certificate, nid int, value string) error {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("x509: certificate closed")
	}
	var sub, iss unsafe.Pointer
	if subject != nil {
		sub = subject.handle.Ptr()
	}
	if issuer != nil {
		iss = issuer.handle.Ptr()
	}
	if !native.X509V3_EXT_conf_nid_ctx(c.handle.Ptr(), sub, iss, nid, value) {
		return NewOpError("x509: X509V3_EXT_conf_nid", native.PopError())
	}
	return nil
}

// MarshalDER 将证书序列化为 ASN.1 DER 编码。
//
// 证书已通过 Close 关闭，或底层 i2d_X509 调用失败时返回错误（包装为 OpError）。
//
// MarshalDER serializes the certificate to its ASN.1 DER encoding.
//
// Returns an error when the certificate has been closed via Close, or
// when the underlying i2d_X509 call fails (wrapped as OpError).
func (c *Certificate) MarshalDER() ([]byte, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: certificate closed")
	}
	der, ok := native.I2d_X509(c.handle.Ptr())
	if !ok {
		return nil, NewOpError("x509: i2d_X509", native.PopError())
	}
	return der, nil
}

// PublicKey 以新 *PKey 返回证书公钥。
//
// 返回值拥有底层 EVP_PKEY 引用，调用方负责调用 Close 释放；底层 X509_get_pubkey 错误以 OpError 包装。
//
// PublicKey returns the public key of the certificate as a fresh *PKey.
//
// The returned PKey owns the underlying EVP_PKEY reference; the caller is
// responsible for calling Close to release it. Errors from the underlying
// X509_get_pubkey call are wrapped as OpError.
func (c *Certificate) PublicKey() (*PKey, error) {
	p := native.X509_get_pubkey(c.handle.Ptr())
	if p == nil {
		return nil, NewOpError("x509: X509_get_pubkey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Close 释放底层 X509 句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的证书调用返回 nil，不产生副作用；Close 返回后，
// 其他方法对该 *Certificate 调用将返回 "x509: certificate closed" 错误（查询类方法返回零值），
// 调用方须保证无并发 goroutine 仍持有该证书的引用。
//
// Close releases the underlying X509 handle.
//
// The call is idempotent: invoking it on a nil receiver or on a
// certificate that has already been closed returns nil without further
// side effects. After Close returns, any other method on the same
// *Certificate returns the error "x509: certificate closed" (or a
// zero-value result for query-style methods), so the caller must
// guarantee that no concurrent goroutine still holds a reference to
// this certificate.
func (c *Certificate) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// CertificateRequest 表示一个证书签名请求（X509_REQ 的包装）。
//
// 类型通过内部 Handle 拥有底层 X509_REQ 句柄；调用完毕后须调用 Close 释放。
//
// CertificateRequest is the Go wrapper around an OpenSSL X509_REQ
// certificate signing request.
//
// The type owns the underlying X509_REQ handle through an internal
// Handle value; callers must invoke Close to release it once they are
// done with the CSR.
type CertificateRequest struct {
	handle *Handle
}

// NewCertificateRequest 创建空 CSR（字段取默认值）。
//
// 返回值拥有底层 X509_REQ 句柄，调用方负责调用 Close 释放；新建对象须填充
// subject/公钥/可选扩展/challenge password 等字段后调用 Sign 签名。
//
// NewCertificateRequest creates an empty *CertificateRequest with
// default fields.
//
// The returned CSR owns the underlying X509_REQ handle and the caller
// is responsible for calling Close to release it. The freshly created
// object must be filled in (subject, public key, optional extensions and
// challenge password) and then signed with Sign.
func NewCertificateRequest() (*CertificateRequest, error) {
	r := native.X509_REQ_new()
	if r == nil {
		return nil, NewOpError("x509: X509_REQ_new", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// LoadCertificateRequestPEM 解析 PEM 编码的证书签名请求（"-----BEGIN CERTIFICATE REQUEST-----"）。
//
// 返回值拥有底层 X509_REQ 句柄，调用方须调用 Close 释放；错误以 OpError 包装。
//
// LoadCertificateRequestPEM parses a PEM-encoded certificate signing
// request ("-----BEGIN CERTIFICATE REQUEST-----").
//
// The returned *CertificateRequest owns the underlying X509_REQ handle
// and the caller must invoke Close to release it. Errors are wrapped as
// OpError.
func LoadCertificateRequestPEM(pem []byte) (*CertificateRequest, error) {
	bio := native.BIO_new_mem_buf(pem)
	if bio == nil {
		return nil, NewOpError("x509: BIO_new_mem_buf", native.PopError())
	}
	defer native.BIO_free(bio)
	r := native.X_PEM_read_bio_X509_REQ(bio)
	if r == nil {
		return nil, NewOpError("x509: PEM_read_bio_X509_REQ", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// LoadCertificateRequestDER 解析 ASN.1 DER 编码的 CSR。
//
// 返回值拥有底层 X509_REQ 句柄，调用方须调用 Close 释放；错误以 OpError 包装。
//
// LoadCertificateRequestDER parses an ASN.1 DER-encoded CSR.
//
// The returned *CertificateRequest owns the underlying X509_REQ handle
// and the caller must invoke Close to release it. Errors are wrapped as
// OpError.
func LoadCertificateRequestDER(der []byte) (*CertificateRequest, error) {
	r := native.D2i_X509_REQ(der)
	if r == nil {
		return nil, NewOpError("x509: d2i_X509_REQ", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// MarshalPEM 将 CSR 序列化为 PEM 编码（"-----BEGIN CERTIFICATE REQUEST-----"）。
//
// CSR 已通过 Close 关闭，或底层 PEM_write_bio_X509_REQ 调用失败时返回错误（以 OpError 包装）。
//
// MarshalPEM serializes the CSR to its PEM encoding
// ("-----BEGIN CERTIFICATE REQUEST-----").
//
// Returns an error if the CSR has been closed via Close, or if the
// underlying PEM_write_bio_X509_REQ call fails (errors are wrapped as
// OpError).
func (r *CertificateRequest) MarshalPEM() ([]byte, error) {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil, fmt.Errorf("x509: request closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_PEM_write_bio_X509_REQ(bio, r.handle.Ptr()) {
		return nil, NewOpError("x509: PEM_write_bio_X509_REQ", native.PopError())
	}
	return readAllBIO(bio)
}

// SetSubject 设置 CSR 的主题名字。
//
// 参数 n 必须是未关闭的有效 Name；否则返回 "x509: invalid subject name" 错误；底层 OpenSSL 调用错误以 OpError 包装。
//
// SetSubject sets the subject Name of the CSR.
//
// The argument n must be a live, non-closed Name; otherwise the call
// returns the error "x509: invalid subject name". Errors from the
// underlying OpenSSL call are wrapped as OpError.
func (r *CertificateRequest) SetSubject(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid subject name")
	}
	if !native.X509_REQ_set_subject_name(r.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_set_subject_name", native.PopError())
	}
	return nil
}

// SubjectName 返回 CSR 的主题名字。
//
// 返回的 *Name 包装了底层 X509_REQ 借用的内部 X509_NAME 指针；调用方不得对其调用 Close，指针在 CSR 生命周期内有效。
//
// SubjectName returns the subject Name of the CSR.
//
// The returned *Name wraps an internal X509_NAME pointer borrowed from
// the underlying X509_REQ; the caller must NOT call Close on it. The
// pointer remains valid for the lifetime of the CSR.
func (r *CertificateRequest) SubjectName() *Name {
	n := native.X509_REQ_get_subject_name(r.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// SetChallengePassword 设置 CSR 的 PKCS#9 challengePassword 属性。
//
// 须在 Sign 之前调用；CSR 已通过 Close 关闭，或底层 OpenSSL 调用失败时返回错误（包装为 OpError）。
//
// SetChallengePassword sets the PKCS#9 challengePassword attribute of
// the CSR.
//
// Must be invoked before Sign. Returns an error when the CSR has been
// closed via Close, or when the underlying OpenSSL call fails (wrapped
// as OpError).
func (r *CertificateRequest) SetChallengePassword(pwd string) error {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return fmt.Errorf("x509: request closed")
	}
	if !native.X509_REQ_set_challenge_password(r.handle.Ptr(), pwd) {
		return NewOpError("x509: X509_REQ_set_challenge_password", native.PopError())
	}
	return nil
}

// ChallengePassword 返回 CSR 挑战密码；未设置返回空串。
//
// ChallengePassword returns the PKCS#9 challengePassword attribute of the
// CSR. Returns the empty string when the CSR has been closed or has no
// challenge password.
func (r *CertificateRequest) ChallengePassword() string {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return ""
	}
	return native.X509_REQ_get_challenge_password(r.handle.Ptr())
}

// AddExtensions 向 CSR 批量追加多个扩展。
//
// 须在 Sign 之前调用；nil 或空 exts 切片为 no-op，返回 nil；每个扩展由 Nid 与 Value（X509V3_EXT_conf 串）构造；任一底层 OpenSSL 调用失败均以 OpError 包装；部分失败时已创建的扩展会在错误返回前全部释放。
//
// AddExtensions appends a batch of extensions to the CSR.
//
// Must be invoked before Sign. A nil or empty exts slice is a no-op and
// returns nil. Each extension is built from its Nid and Value (the
// X509V3_EXT_conf string). Errors from any of the underlying OpenSSL
// calls are wrapped as OpError. If the call fails partway through, every
// extension created so far is released before the error is returned.
func (r *CertificateRequest) AddExtensions(exts ...Extension) error {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return fmt.Errorf("x509: request closed")
	}
	if len(exts) == 0 {
		return nil
	}
	sk := native.X509_sk_X509_EXTENSION_new_null()
	if sk == nil {
		return NewOpError("x509: sk_X509_EXTENSION_new_null", native.PopError())
	}
	defer native.X509_sk_X509_EXTENSION_free(sk)
	// 扩展压栈后不能立即释放：X509_REQ_add_extensions 在编码时会读取栈中元素。
	created := make([]unsafe.Pointer, 0, len(exts))
	freeAll := func() {
		for _, x := range created {
			native.X509_EXTENSION_free(x)
		}
	}
	for _, e := range exts {
		ext := native.X509V3_EXT_conf_nid(e.Nid, e.Value)
		if ext == nil {
			freeAll()
			return NewOpError("x509: X509V3_EXT_conf_nid", native.PopError())
		}
		created = append(created, ext)
		if !native.X509_sk_X509_EXTENSION_push(sk, ext) {
			freeAll()
			return NewOpError("x509: sk_X509_EXTENSION_push", native.PopError())
		}
	}
	if !native.X509_REQ_add_extensions(r.handle.Ptr(), sk) {
		freeAll()
		return NewOpError("x509: X509_REQ_add_extensions", native.PopError())
	}
	freeAll()
	return nil
}

// AddExtension 向 CSR 追加单个扩展。
//
// nid 为扩展 NID，value 为 X509V3_EXT_conf 配置串；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddExtension appends a single extension to the CSR.
//
// Must be invoked before Sign. nid is the extension NID; value is the
// X509V3_EXT_conf configuration string. Errors from the underlying
// OpenSSL call are wrapped as OpError.
func (r *CertificateRequest) AddExtension(nid int, value string) error {
	return r.AddExtensions(Extension{Nid: nid, Value: value})
}

// AddSubjectAltName 向 CSR 追加 subjectAltName 扩展。
//
// value 为 OpenSSL 逗号分隔的 SAN 列表（如 "DNS:example.com"）；须在 Sign 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddSubjectAltName appends a subjectAltName extension to the CSR.
//
// value is the OpenSSL comma-separated SAN list (for example
// "DNS:example.com"). Must be invoked before Sign. Errors from the
// underlying OpenSSL call are wrapped as OpError.
func (r *CertificateRequest) AddSubjectAltName(value string) error {
	return r.AddExtension(native.NidSubjectAltName, value)
}

// Extensions 返回 CSR 的 extensionRequest 属性中列出的全部扩展。
//
// 对 nil 或已关闭的 CSR，以及无 extensionRequest 属性时返回 nil；每条包含扩展 NID、短名、critical 标志及 DER 字节。
//
// Extensions returns every extension listed in the CSR's
// extensionRequest attribute.
//
// The result is nil for a nil or closed CSR, or when no extensionRequest
// attribute is present. Each entry contains the extension NID, short
// name, critical flag and DER bytes.
func (r *CertificateRequest) Extensions() []Extension {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil
	}
	sk := native.X509_REQ_get_extensions(r.handle.Ptr())
	if sk == nil {
		return nil
	}
	defer native.X509_sk_X509_EXTENSION_pop_free(sk)
	count := native.X509_sk_X509_EXTENSION_num(sk)
	out := make([]Extension, 0, count)
	for i := 0; i < count; i++ {
		e := native.X509_sk_X509_EXTENSION_value(sk, i)
		if e == nil {
			continue
		}
		nid := native.OBJ_obj2nid(native.X509_EXTENSION_get_object(e))
		out = append(out, Extension{
			Nid:      nid,
			Field:    native.OBJ_nid2sn(nid),
			Critical: native.X509_EXTENSION_get_critical(e) != 0,
			Data:     native.ASN1_STRING_data_bytes(native.X509_EXTENSION_get_data(e)),
		})
	}
	return out
}

// MarshalDER 将 CSR 序列化为 ASN.1 DER 编码。
//
// CSR 已通过 Close 关闭，或底层 i2d_X509_REQ 调用失败时返回错误（包装为 OpError）。
//
// MarshalDER serializes the CSR to its ASN.1 DER encoding.
//
// Returns an error when the CSR has been closed via Close, or when the
// underlying i2d_X509_REQ call fails (wrapped as OpError).
func (r *CertificateRequest) MarshalDER() ([]byte, error) {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil, fmt.Errorf("x509: request closed")
	}
	der, ok := native.I2d_X509_REQ(r.handle.Ptr())
	if !ok {
		return nil, NewOpError("x509: i2d_X509_REQ", native.PopError())
	}
	return der, nil
}

// SetPublicKey 关联 CSR 的公钥。
//
// 参数 k 必须是未关闭的有效 PKey；否则返回 "x509: invalid public key" 错误；底层 OpenSSL 调用错误以 OpError 包装。
//
// SetPublicKey associates the CSR with the given *PKey.
//
// The argument k must be a live, non-closed PKey; otherwise the call
// returns the error "x509: invalid public key". Errors from the
// underlying OpenSSL call are wrapped as OpError.
func (r *CertificateRequest) SetPublicKey(k *PKey) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_REQ_set_pubkey(r.handle.Ptr(), k.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_set_pubkey", native.PopError())
	}
	return nil
}

// Sign 使用请求者私钥对 CSR 签名。
//
// priv 必须是未关闭的有效 PKey；md 传 nil 时按签名密钥类型自动选择（SM2→SM3，RSA/ECDSA→SHA256）；底层 X509_REQ_sign 调用错误以 OpError 包装。
//
// Sign signs the CSR with the requester's private key.
//
// priv must be a live, non-closed PKey. When md is nil the digest is
// selected automatically by signer type (SM2→SM3, RSA/ECDSA→SHA256).
// Errors from the underlying X509_REQ_sign call are wrapped as OpError.
func (r *CertificateRequest) Sign(priv *PKey, md *Digest) error {
	if priv == nil || priv.handle == nil || priv.handle.IsClosed() {
		return fmt.Errorf("x509: invalid private key")
	}
	if md == nil {
		md = digestForSigner(priv)
	}
	if md == nil || md.handle == nil {
		return fmt.Errorf("x509: invalid digest")
	}
	if !native.X509_REQ_sign(r.handle.Ptr(), priv.handle.Ptr(), md.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_sign", native.PopError())
	}
	return nil
}

// Verify 使用 CSR 自身公钥验证签名。
//
// 注意：Tongsuo 8.5-pre1 的 X509_REQ_verify 对 SM2 证书签名请求存在缺陷
// （返回 -1），故此处手动重建 CertificationRequestInfo 的 DER 并按密钥
// 类型选择摘要验签（结果与 openssl req -verify 一致）。
//
// Verify checks the CSR signature against its own embedded public key.
//
// Note: Tongsuo 8.5-pre1's X509_REQ_verify has a known defect for SM2
// CSRs (it returns -1), so this implementation rebuilds the
// CertificationRequestInfo DER manually and dispatches to the correct
// signature path (SM2→Verify with empty user id, RSA/ECDSA→VerifyDigest
// with digestForSigner). The result matches `openssl req -verify`.
func (r *CertificateRequest) Verify() error {
	info, ok := native.I2d_X509_REQ_INFO(r.handle.Ptr())
	if !ok {
		return NewOpError("x509: i2d_X509_REQ_INFO", native.PopError())
	}
	sig, ok := native.X509_REQ_get0_signature(r.handle.Ptr())
	if !ok {
		return NewOpError("x509: X509_REQ_get0_signature", native.PopError())
	}
	pub := native.X509_REQ_get_pubkey(r.handle.Ptr())
	if pub == nil {
		return NewOpError("x509: X509_REQ_get_pubkey", native.PopError())
	}
	pkey := &PKey{handle: NewHandle(pub, true, native.EVP_PKEY_free)}
	defer pkey.Close()
	// SM2 走带 userId 的路径；RSA/ECDSA 按类型选摘要。
	if pkey.TypeID() == native.EvpPkeySM2 {
		return pkey.Verify(info, sig, nil)
	}
	return pkey.VerifyDigest(info, sig, digestForSigner(pkey))
}

// PublicKey 以新 *PKey 返回 CSR 内嵌的公钥。
//
// 返回值拥有底层 EVP_PKEY 引用，调用方负责调用 Close 释放；底层 X509_REQ_get_pubkey 错误以 OpError 包装。
//
// PublicKey returns the public key embedded in the CSR as a fresh *PKey.
//
// The returned PKey owns the underlying EVP_PKEY reference; the caller
// is responsible for calling Close to release it. Errors from the
// underlying X509_REQ_get_pubkey call are wrapped as OpError.
func (r *CertificateRequest) PublicKey() (*PKey, error) {
	p := native.X509_REQ_get_pubkey(r.handle.Ptr())
	if p == nil {
		return nil, NewOpError("x509: X509_REQ_get_pubkey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Signature 返回 CSR 的原始签名字节（ASN.1 BIT STRING 内容，DER 编码）。
//
// 对 nil 或已关闭的 CSR 返回 nil；不可用时同样返回 nil，不返回错误。
//
// Signature returns the raw signature bytes of the CSR (the contents of
// the ASN.1 BIT STRING, i.e. the DER-encoded signature).
//
// The result is nil for a nil or closed CSR, and also nil when the
// signature is unavailable; the call never reports an error.
func (r *CertificateRequest) Signature() []byte {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return nil
	}
	sig, _, _ := native.X509_REQ_get_signature_info(r.handle.Ptr())
	return sig
}

// SignatureAlgorithm 返回 CSR 签名算法的短名（如 "SM2-SM3"、"RSA-SHA256"、"ecdsa-with-SHA256"）。
//
// 对 nil 或已关闭的 CSR 返回空字符串；OpenSSL 无法识别签名算法时同样返回空字符串。返回值取自 OBJ_nid2_sn。
//
// SignatureAlgorithm returns the CSR signature algorithm short name
// (for example "SM2-SM3", "RSA-SHA256", or "ecdsa-with-SHA256").
//
// The result is the empty string for a nil or closed CSR, and also
// when the signature algorithm is not recognized by OpenSSL. The value
// comes from OBJ_nid2_sn.
func (r *CertificateRequest) SignatureAlgorithm() string {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return ""
	}
	_, nid, _ := native.X509_REQ_get_signature_info(r.handle.Ptr())
	return native.OBJ_nid2sn(nid)
}

// SignatureAlgorithmOID 返回 CSR 签名算法的 OID 点分文本（如 "1.2.156.10197.1.501"、"1.2.840.113549.1.1.11"）。
//
// 对 nil 或已关闭的 CSR 返回空字符串；OpenSSL 无法读取算法 OID 时同样返回空字符串。返回值取自 OBJ_obj2txt(_, _, _, 1)。
//
// SignatureAlgorithmOID returns the CSR signature algorithm OID as a
// dotted string (for example "1.2.156.10197.1.501" for SM2-with-SM3
// or "1.2.840.113549.1.1.11" for sha256WithRSAEncryption).
//
// The result is the empty string for a nil or closed CSR, and also
// when the signature algorithm OID cannot be read. The value comes
// from OBJ_obj2txt(_, _, _, 1).
func (r *CertificateRequest) SignatureAlgorithmOID() string {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return ""
	}
	_, _, oid := native.X509_REQ_get_signature_info(r.handle.Ptr())
	return oid
}

// Close 释放底层 X509_REQ 句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的 CSR 调用返回 nil，不产生副作用；Close 返回后，
// 其他方法对该 *CertificateRequest 调用将返回 "x509: request closed" 错误（查询类方法返回零值），
// 调用方须保证无并发 goroutine 仍持有该 CSR 的引用。
//
// Close releases the underlying X509_REQ handle.
//
// The call is idempotent: invoking it on a nil receiver or on a CSR
// that has already been closed returns nil without further side
// effects. After Close returns, any other method on the same
// *CertificateRequest returns the error "x509: request closed" (or a
// zero-value result for query-style methods), so the caller must
// guarantee that no concurrent goroutine still holds a reference to
// this CSR.
func (r *CertificateRequest) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}

// readAllBIO 读取 BIO 内全部数据到字节切片。
//
// readAllBIO drains the OpenSSL memory BIO into a byte slice. Returns
// "x509: empty BIO output" if the BIO yields no data, or an error
// wrapping an OpError on read failure.
func readAllBIO(bio unsafe.Pointer) ([]byte, error) {
	var out []byte
	tmp := make([]byte, 1024)
	for {
		n := native.BIO_read(bio, tmp)
		if n <= 0 {
			break
		}
		out = append(out, tmp[:n]...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("x509: empty BIO output")
	}
	return out, nil
}

// VerifyError 表示 ChainVerify 报告的证书链验证失败详情。
//
// Code 为 X509_V_ERR_* 错误码（如 native.X509VErrCertHasExpired）；Depth 为出错深度（0 表示待验证证书本身）；Message 为 X509_verify_cert_error_string 给出的人类可读错误描述。
//
// VerifyError carries the details of a failed certificate-chain
// verification performed by ChainVerify.
//
// Code holds the X509_V_ERR_* error code (for example
// native.X509VErrCertHasExpired); Depth holds the depth at which the
// error occurred (0 for the leaf certificate being verified); Message
// is the human-readable error string from X509_verify_cert_error_string.
type VerifyError struct {
	Code    int    // X509_V_ERR_* 错误码（如 native.X509VErrCertHasExpired）
	Depth   int    // 出错深度（0 为待验证证书本身）
	Message string // 错误描述
}

// Error 实现 error 接口。
//
// Error formats the VerifyError as "x509: certificate verify failed:
// <message> (code=<code>, depth=<depth>)". Calling Error on a nil
// receiver returns the fallback "x509: verify error".
func (e *VerifyError) Error() string {
	if e == nil {
		return "x509: verify error"
	}
	return fmt.Sprintf("x509: certificate verify failed: %s (code=%d, depth=%d)",
		e.Message, e.Code, e.Depth)
}

// Store 表示证书信任存储（X509_STORE 的包装），作为 ChainVerify 的信任锚集合。
//
// 类型通过内部 Handle 拥有底层 X509_STORE 句柄；调用完毕后须调用 Close 释放。
//
// Store is the Go wrapper around an OpenSSL X509_STORE and acts as the
// trust anchor collection for ChainVerify.
//
// The type owns the underlying X509_STORE handle through an internal
// Handle value; callers must invoke Close to release it once they are
// done with the Store.
type Store struct {
	handle *Handle
}

// NewStore 创建空的信任存储（不含任何证书或 CRL）。
//
// 返回值拥有底层 X509_STORE 句柄，调用方负责调用 Close 释放。
//
// NewStore creates an empty trust Store with no certificates or CRLs.
//
// The returned *Store owns the underlying X509_STORE handle and the
// caller is responsible for calling Close to release it.
func NewStore() (*Store, error) {
	s := native.X509_STORE_new()
	if s == nil {
		return nil, NewOpError("x509: X509_STORE_new", native.PopError())
	}
	return &Store{handle: NewHandle(s, true, native.X509_STORE_free)}, nil
}

// AddCert 向存储添加信任证书（通常为根 CA）。
//
// s 与 c 均必须是未关闭的有效对象；否则分别返回 "x509: store closed" 或 "x509: invalid certificate" 错误；底层 X509_STORE_add_cert 错误以 OpError 包装。
//
// AddCert inserts a trusted certificate (typically a root CA) into the
// Store.
//
// Both s and c must be live, non-closed objects; otherwise the call
// returns the error "x509: store closed" or "x509: invalid certificate".
// Errors from the underlying X509_STORE_add_cert call are wrapped as
// OpError.
func (s *Store) AddCert(c *Certificate) error {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return fmt.Errorf("x509: store closed")
	}
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("x509: invalid certificate")
	}
	if !native.X509_STORE_add_cert(s.handle.Ptr(), c.handle.Ptr()) {
		return NewOpError("x509: X509_STORE_add_cert", native.PopError())
	}
	return nil
}

// AddCRL 向存储添加 CRL 用于吊销检查。
//
// 配合 SetFlags(native.X509VFlagCRLCheck 或 native.X509VFlagCRLCheckAll) 启用 ChainVerify 中的 CRL 吊销检查；s 与 c 均必须是未关闭的有效对象；底层 X509_STORE_add_crl 错误以 OpError 包装。
//
// AddCRL inserts a CRL into the Store for revocation checks.
//
// Combine with SetFlags(native.X509VFlagCRLCheck or X509VFlagCRLCheckAll)
// to enable CRL-based revocation checking in ChainVerify. Both s and c
// must be live, non-closed objects; errors from the underlying
// X509_STORE_add_crl call are wrapped as OpError.
func (s *Store) AddCRL(c *CRL) error {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return fmt.Errorf("x509: store closed")
	}
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("x509: invalid CRL")
	}
	if !native.X509_STORE_add_crl(s.handle.Ptr(), c.handle.Ptr()) {
		return NewOpError("x509: X509_STORE_add_crl", native.PopError())
	}
	return nil
}

// SetFlags 配置存储的验证标志。
//
// 传入 native.X509VFlagCRLCheck 或 native.X509VFlagCRLCheckAll 启用 CRL 吊销检查（需先用 AddCRL 加载相关 CRL）；存储必须是未关闭的有效对象；底层 X509_STORE_set_flags 错误以 OpError 包装。
//
// SetFlags configures the verification flags of the Store.
//
// Pass native.X509VFlagCRLCheck or native.X509VFlagCRLCheckAll to enable
// CRL-based revocation checks (after loading the relevant CRLs via
// AddCRL). The Store must be live and non-closed; errors from the
// underlying X509_STORE_set_flags call are wrapped as OpError.
func (s *Store) SetFlags(flags uint64) error {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return fmt.Errorf("x509: store closed")
	}
	if !native.X509_STORE_set_flags(s.handle.Ptr(), flags) {
		return NewOpError("x509: X509_STORE_set_flags", native.PopError())
	}
	return nil
}

// Close 释放底层 X509_STORE 句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的存储调用返回 nil，不产生副作用；Close 返回后，
// 其他方法对该 *Store 调用将返回 "x509: store closed" 错误（AddCert 类方法返回 false），
// 调用方须保证无并发 goroutine 仍持有该存储的引用。
//
// Close releases the underlying X509_STORE handle.
//
// The call is idempotent: invoking it on a nil receiver or on a Store
// that has already been closed returns nil without further side
// effects. After Close returns, any other method on the same *Store
// returns the error "x509: store closed" (or false for AddCert-style
// methods), so the caller must guarantee that no concurrent goroutine
// still holds a reference to this Store.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.handle.Close()
}

// ChainVerify 验证证书链并返回已构建的完整链（索引 0 为叶证书，末位为信任根）。
//
// store 提供信任锚（根 CA）；intermediates 提供可选的中间 CA 链用于补全缺失环节；cert、store 及每个 intermediate 均必须是未关闭的有效对象；验证成功时返回的切片由调用方拥有（每张 *Certificate 须单独 Close）；验证失败时返回 *VerifyError，携带 X509_V_ERR_* 错误码、深度及描述信息。
//
// ChainVerify validates the certificate chain and returns the completed
// chain with index 0 being the leaf certificate and the last element
// being the trust root.
//
// store provides the trust anchors (root CAs); intermediates supplies
// the optional CA chain used to fill in missing links. cert, store and
// every intermediate must be live, non-closed objects. On success the
// returned slice contains fresh *Certificate copies owned by the caller
// (each must be closed individually). On verification failure the error
// is a *VerifyError carrying the X509_V_ERR_* code, depth and message.
func ChainVerify(cert *Certificate, store *Store, intermediates []*Certificate) ([]*Certificate, error) {
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return nil, fmt.Errorf("x509: invalid certificate")
	}
	if store == nil || store.handle == nil || store.handle.IsClosed() {
		return nil, fmt.Errorf("x509: invalid trust store")
	}
	ctx := native.X509_STORE_CTX_new()
	if ctx == nil {
		return nil, NewOpError("x509: X509_STORE_CTX_new", native.PopError())
	}
	defer native.X509_STORE_CTX_free(ctx)
	if !native.X509_STORE_CTX_init(ctx, store.handle.Ptr(), cert.handle.Ptr()) {
		return nil, NewOpError("x509: X509_STORE_CTX_init", native.PopError())
	}
	if len(intermediates) > 0 {
		sk := native.X509_sk_X509_new_null()
		if sk == nil {
			return nil, NewOpError("x509: sk_X509_new_null", native.PopError())
		}
		ok := true
		for _, ic := range intermediates {
			if ic == nil || ic.handle == nil || ic.handle.IsClosed() {
				ok = false
				break
			}
			if !native.X509_sk_X509_push(sk, ic.handle.Ptr()) {
				ok = false
				break
			}
		}
		if !ok {
			native.X509_sk_X509_free(sk)
			return nil, fmt.Errorf("x509: invalid intermediate certificate")
		}
		// 所有权转移给 ctx，ctx 释放时一并释放栈（不释放元素）。
		native.X509_STORE_CTX_set0_untrusted(ctx, sk)
	}
	ret := native.X509_verify_cert(ctx)
	if ret != 1 {
		code := native.X509_STORE_CTX_get_error(ctx)
		depth := native.X509_STORE_CTX_get_error_depth(ctx)
		msg := native.X509_verify_cert_error_string(code)
		return nil, &VerifyError{Code: code, Depth: depth, Message: msg}
	}
	// 链补全：复制已验证链。
	chainSk := native.X509_STORE_CTX_get0_chain(ctx)
	if chainSk == nil {
		return nil, fmt.Errorf("x509: X509_STORE_CTX_get0_chain returned nil")
	}
	count := native.X509_sk_X509_num(chainSk)
	chain := make([]*Certificate, 0, count)
	for i := 0; i < count; i++ {
		x := native.X509_sk_X509_value(chainSk, i)
		if x == nil {
			continue
		}
		dup := native.X509_dup(x)
		if dup == nil {
			return nil, NewOpError("x509: X509_dup", native.PopError())
		}
		chain = append(chain, &Certificate{handle: NewHandle(dup, true, native.X509_free)})
	}
	return chain, nil
}

// crlReasonNames 为 CRL 吊销原因码到名称的映射（与 openssl crl -text 输出一致）。
//
// crlReasonNames maps RFC 5280 CRLReason codes (0–10) to their textual
// names, matching the human-readable output of `openssl crl -text`.
var crlReasonNames = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "CACompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	6:  "certificateHold",
	8:  "removeFromCRL",
	9:  "privilegeWithdrawn",
	10: "aACompromise",
}

// RevokedEntry 表示 CRL 中的一条吊销记录。
//
// Serial 为被吊销证书的序列号；RevocationDate 为 UTC 吊销日期；ReasonCode 为 CRL reason code（未指定时为 -1）；Reason 为对应的长名（如 "keyCompromise"），code 未映射时为空字符串。
//
// RevokedEntry is one revocation record in a CRL.
//
// Serial is the revoked certificate's serial number; RevocationDate is
// the UTC date of revocation; ReasonCode is the CRL reason code (-1 when
// unspecified); Reason is the matching long name (for example
// "keyCompromise"), or the empty string when the code is unmapped.
type RevokedEntry struct {
	Serial         int64
	RevocationDate time.Time
	ReasonCode     int    // -1 表示未指定
	Reason         string // 原因名（如 "keyCompromise"）
}

// CRL 表示证书吊销列表（X509_CRL 的包装）。
//
// 类型通过内部 Handle 拥有底层 X509_CRL 句柄；调用完毕后须调用 Close 释放。
//
// CRL is the Go wrapper around an OpenSSL X509_CRL certificate
// revocation list.
//
// The type owns the underlying X509_CRL handle through an internal Handle
// value; callers must invoke Close to release it once they are done
// with the CRL.
type CRL struct {
	handle *Handle
}

// LoadCRLPEM 解析 PEM 编码的 CRL（"-----BEGIN X509 CRL-----"）。
//
// 返回值拥有底层 X509_CRL 句柄，调用方须调用 Close 释放；错误以 OpError 包装。
//
// LoadCRLPEM parses a PEM-encoded CRL
// ("-----BEGIN X509 CRL-----").
//
// The returned *CRL owns the underlying X509_CRL handle and the caller
// must invoke Close to release it. Errors are wrapped as OpError.
func LoadCRLPEM(pem []byte) (*CRL, error) {
	bio := native.BIO_new_mem_buf(pem)
	if bio == nil {
		return nil, NewOpError("x509: BIO_new_mem_buf", native.PopError())
	}
	defer native.BIO_free(bio)
	c := native.X_PEM_read_bio_X509_CRL(bio)
	if c == nil {
		return nil, NewOpError("x509: PEM_read_bio_X509_CRL", native.PopError())
	}
	return &CRL{handle: NewHandle(c, true, native.X509_CRL_free)}, nil
}

// NewCRL 创建并签发一张空的 CRL（不含吊销条目），适用于测试 / 工具链。
//
// issuer 为签发者名字（直接借用其底层 X509_NAME，不复制；调用方须保证 issuer 在 Sign 后仍有效）；
// priv 为签发者私钥（必须是未关闭的有效 *PKey）；thisUpdate / nextUpdate 为 CRL 生效与过期时间；
// 返回的 CRL 默认 version = v2，并自动附加 CRL Number 扩展（值 = 1，匹配 `openssl ca -gencrl` 的默认行为）。
//
// 返回值拥有底层 X509_CRL 句柄，调用方负责 Close 释放；错误以 OpError 包装。
//
// NewCRL creates and signs an empty CRL (no revoked entries) for testing
// or tooling purposes.
//
// issuer is the issuer name (its underlying X509_NAME is borrowed, not
// duplicated, so the caller must keep issuer alive through Sign); priv
// is the issuer private key (must be a live, non-closed *PKey);
// thisUpdate / nextUpdate define the CRL time window. The returned CRL
// defaults to v2 and includes a CRL Number extension set to 1 (matching
// the default behavior of `openssl ca -gencrl`). The returned *CRL owns
// its handle and the caller must invoke Close to release it. Errors are
// wrapped as OpError.
func NewCRL(issuer *Name, priv *PKey, thisUpdate, nextUpdate time.Time) (*CRL, error) {
	if issuer == nil || issuer.handle == nil || issuer.handle.IsClosed() {
		return nil, fmt.Errorf("x509: invalid issuer name")
	}
	if priv == nil || priv.handle == nil || priv.handle.IsClosed() {
		return nil, fmt.Errorf("x509: invalid signing key")
	}
	c := native.X509_CRL_new()
	if c == nil {
		return nil, NewOpError("x509: X509_CRL_new", native.PopError())
	}
	crl := &CRL{handle: NewHandle(c, true, native.X509_CRL_free)}
	if !native.X509_CRL_set_version(c, 1) { // v2
		crl.Close()
		return nil, NewOpError("x509: X509_CRL_set_version", native.PopError())
	}
	if !native.X509_CRL_set_issuer_name(c, issuer.handle.Ptr()) {
		crl.Close()
		return nil, NewOpError("x509: X509_CRL_set_issuer_name", native.PopError())
	}
	if !native.X509_CRL_set1_lastUpdate(c, thisUpdate.Unix()) {
		crl.Close()
		return nil, NewOpError("x509: X509_CRL_set1_lastUpdate", native.PopError())
	}
	if !nextUpdate.IsZero() {
		if !native.X509_CRL_set1_nextUpdate(c, nextUpdate.Unix()) {
			crl.Close()
			return nil, NewOpError("x509: X509_CRL_set1_nextUpdate", native.PopError())
		}
	}
	// 附加 CRL Number 扩展（值 = 1），匹配 openssl ca -gencrl 默认行为
	if !native.X509_CRL_set_crl_number(c, 1) {
		crl.Close()
		return nil, NewOpError("x509: CRL Number extension", native.PopError())
	}
	md := digestForSigner(priv)
	if md == nil || md.handle == nil {
		crl.Close()
		return nil, fmt.Errorf("x509: invalid digest for signer")
	}
	if !native.X509_CRL_sign(c, priv.handle.Ptr(), md.handle.Ptr()) {
		crl.Close()
		return nil, NewOpError("x509: X509_CRL_sign", native.PopError())
	}
	return crl, nil
}

// LoadCRLDER 解析 ASN.1 DER 编码的 CRL。
//
// 返回值拥有底层 X509_CRL 句柄，调用方须调用 Close 释放；错误以 OpError 包装。
//
// LoadCRLDER parses an ASN.1 DER-encoded CRL.
//
// The returned *CRL owns the underlying X509_CRL handle and the caller
// must invoke Close to release it. Errors are wrapped as OpError.
func LoadCRLDER(der []byte) (*CRL, error) {
	c := native.D2i_X509_CRL(der)
	if c == nil {
		return nil, NewOpError("x509: d2i_X509_CRL", native.PopError())
	}
	return &CRL{handle: NewHandle(c, true, native.X509_CRL_free)}, nil
}

// MarshalPEM 将 CRL 序列化为 PEM 编码（"-----BEGIN X509 CRL-----"）。
//
// CRL 已通过 Close 关闭，或底层 PEM_write_bio_X509_CRL 调用失败时返回错误（以 OpError 包装）。
//
// MarshalPEM serializes the CRL to its PEM encoding
// ("-----BEGIN X509 CRL-----").
//
// Returns an error when the CRL has been closed via Close, or when the
// underlying PEM_write_bio_X509_CRL call fails (errors are wrapped as
// OpError).
func (c *CRL) MarshalPEM() ([]byte, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: CRL closed")
	}
	bio := native.BIO_new(native.BIO_s_mem())
	if bio == nil {
		return nil, NewOpError("x509: BIO_new", native.PopError())
	}
	defer native.BIO_free(bio)
	if !native.X_PEM_write_bio_X509_CRL(bio, c.handle.Ptr()) {
		return nil, NewOpError("x509: PEM_write_bio_X509_CRL", native.PopError())
	}
	return readAllBIO(bio)
}

// MarshalDER 将 CRL 序列化为 ASN.1 DER 编码。
//
// CRL 已通过 Close 关闭，或底层 i2d_X509_CRL 调用失败时返回错误（以 OpError 包装）。
//
// MarshalDER serializes the CRL to its ASN.1 DER encoding.
//
// Returns an error when the CRL has been closed via Close, or when the
// underlying i2d_X509_CRL call fails (errors are wrapped as OpError).
func (c *CRL) MarshalDER() ([]byte, error) {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil, fmt.Errorf("x509: CRL closed")
	}
	der, ok := native.I2d_X509_CRL(c.handle.Ptr())
	if !ok {
		return nil, NewOpError("x509: i2d_X509_CRL", native.PopError())
	}
	return der, nil
}

// AddAuthorityKeyID 向 CRL 追加 authorityKeyIdentifier 扩展（keyid 取自 issuer 的 SKID 或公钥）。
//
// issuer 必须是已设置公钥的未关闭 *Certificate（推荐先对 issuer 调用 AddSubjectKeyID）；
// 必须在 MarshalPEM / MarshalDER 之前调用；底层 OpenSSL 错误以 OpError 包装。
//
// AddAuthorityKeyID appends an authorityKeyIdentifier extension to the CRL
// whose keyid is taken from issuer's SKID (preferred) or derived from
// the issuer's public key.
//
// issuer must be a live, non-closed *Certificate with a public key
// configured (AddSubjectKeyID is recommended). Must be invoked before
// MarshalPEM / MarshalDER. Errors from the underlying OpenSSL call are
// wrapped as OpError.
func (c *CRL) AddAuthorityKeyID(issuer *Certificate) error {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return fmt.Errorf("x509: CRL closed")
	}
	if issuer == nil || issuer.handle == nil || issuer.handle.IsClosed() {
		return fmt.Errorf("x509: invalid issuer certificate")
	}
	if !native.X509V3_EXT_conf_nid_ctx_crl(c.handle.Ptr(), issuer.handle.Ptr(),
		native.NidAuthorityKeyIdentifier, "keyid:always") {
		return NewOpError("x509: X509V3_EXT_conf_nid (CRL AKID)", native.PopError())
	}
	return nil
}

// Issuer 返回 CRL 的签发者名字。
//
// 返回的 *Name 包装了底层 X509_CRL 借用的内部 X509_NAME 指针；调用方不得对其调用 Close，指针在 CRL 生命周期内有效。
//
// Issuer returns the issuer Name of the CRL.
//
// The returned *Name wraps an internal X509_NAME pointer borrowed from
// the underlying X509_CRL; the caller must NOT call Close on it. The
// pointer remains valid for the lifetime of the CRL.
func (c *CRL) Issuer() *Name {
	n := native.X509_CRL_get_issuer(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// Version 返回 CRL 版本字段值（0=v1，1=v2）。
//
// Version returns the CRL version field: 0 for v1, 1 for v2.
func (c *CRL) Version() int {
	return native.X509_CRL_get_version(c.handle.Ptr())
}

// LastUpdate 返回 CRL 生效时间。
//
// LastUpdate returns the CRL "lastUpdate" time in UTC.
func (c *CRL) LastUpdate() time.Time {
	return time.Unix(native.X509_CRL_get0_lastUpdate(c.handle.Ptr()), 0).UTC()
}

// NextUpdate 返回 CRL 过期时间。
//
// NextUpdate returns the CRL "nextUpdate" time in UTC.
func (c *CRL) NextUpdate() time.Time {
	return time.Unix(native.X509_CRL_get0_nextUpdate(c.handle.Ptr()), 0).UTC()
}

// RevokedEntries 返回 CRL 中的全部吊销记录。
//
// 对 nil 或已关闭的 CRL，以及不含吊销记录时返回 nil；每条包含序列号、吊销日期、reason code 与人类可读的原因名。
//
// RevokedEntries returns every revocation record in the CRL.
//
// The result is nil for a nil or closed CRL, or when the CRL contains no
// revoked entries. Each entry contains the serial number, revocation
// date, reason code and human-readable reason name.
func (c *CRL) RevokedEntries() []RevokedEntry {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	sk := native.X509_CRL_get_REVOKED(c.handle.Ptr())
	if sk == nil {
		return nil
	}
	count := native.X509_sk_X509_REVOKED_num(sk)
	out := make([]RevokedEntry, 0, count)
	for i := 0; i < count; i++ {
		rev := native.X509_sk_X509_REVOKED_value(sk, i)
		if rev == nil {
			continue
		}
		code := native.X509_REVOKED_crl_reason(rev)
		entry := RevokedEntry{
			Serial:         native.X509_REVOKED_get0_serialNumber(rev),
			RevocationDate: time.Unix(native.X509_REVOKED_get0_revocationDate(rev), 0).UTC(),
			ReasonCode:     code,
			Reason:         crlReasonNames[code],
		}
		out = append(out, entry)
	}
	return out
}

// Signature 返回 CRL 的原始签名字节（ASN.1 BIT STRING 内容，DER 编码）。
//
// 对 nil 或已关闭的 CRL 返回 nil；不可用时同样返回 nil，不返回错误。
//
// Signature returns the raw signature bytes of the CRL (the contents of
// the ASN.1 BIT STRING, i.e. the DER-encoded signature).
//
// The result is nil for a nil or closed CRL, and also nil when the
// signature is unavailable; the call never reports an error.
func (c *CRL) Signature() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	sig, _, _ := native.X509_CRL_get_signature_info(c.handle.Ptr())
	return sig
}

// SignatureAlgorithm 返回 CRL 签名算法的短名（如 "SM2-SM3"、"RSA-SHA256"、"ecdsa-with-SHA256"）。
//
// 对 nil 或已关闭的 CRL 返回空字符串；OpenSSL 无法识别签名算法时同样返回空字符串。
//
// SignatureAlgorithm returns the CRL signature algorithm short name
// (for example "SM2-SM3", "RSA-SHA256", or "ecdsa-with-SHA256").
//
// The result is the empty string for a nil or closed CRL, and also when
// the signature algorithm is not recognized by OpenSSL. The value
// comes from OBJ_nid2_sn.
func (c *CRL) SignatureAlgorithm() string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return ""
	}
	_, nid, _ := native.X509_CRL_get_signature_info(c.handle.Ptr())
	return native.OBJ_nid2sn(nid)
}

// SignatureAlgorithmOID 返回 CRL 签名算法的 OID 点分文本（如 "1.2.156.10197.1.501"、"1.2.840.113549.1.1.11"）。
//
// 对 nil 或已关闭的 CRL 返回空字符串；OpenSSL 无法读取算法 OID 时同样返回空字符串。
//
// SignatureAlgorithmOID returns the CRL signature algorithm OID as a
// dotted string (for example "1.2.156.10197.1.501" for SM2-with-SM3
// or "1.2.840.113549.1.1.11" for sha256WithRSAEncryption).
//
// The result is the empty string for a nil or closed CRL, and also when
// the signature algorithm OID cannot be read. The value comes from
// OBJ_obj2txt(_, _, _, 1).
func (c *CRL) SignatureAlgorithmOID() string {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return ""
	}
	_, _, oid := native.X509_CRL_get_signature_info(c.handle.Ptr())
	return oid
}

// AuthorityKeyID 返回 authorityKeyIdentifier 扩展中 keyid 的字节；无则返回 nil。
//
// AuthorityKeyID returns the keyid bytes of the authorityKeyIdentifier
// extension, or nil when the extension is absent or has no keyid
// component.
func (c *CRL) AuthorityKeyID() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	return native.X509_CRL_get0_authority_key_id(c.handle.Ptr())
}

// Number 返回 CRL Number 扩展的整数值（RFC 5280 §5.2.3）。
// 无 CRL Number 扩展或已关闭 CRL 返回 -1。
//
// Number returns the integer value of the CRL Number extension
// (RFC 5280 §5.2.3), or -1 when the CRL has no CRL Number extension or
// has been closed via Close.
func (c *CRL) Number() int64 {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return -1
	}
	ai := native.X509_CRL_get_crl_number(c.handle.Ptr())
	if ai == nil {
		return -1
	}
	defer native.ASN1_INTEGER_free(ai)
	return native.ASN1_INTEGER_get(ai)
}

// Extensions 按出现顺序返回 CRL 的全部扩展。
//
// 对 nil 或已关闭的 CRL 返回 nil；每条包含扩展 NID、短名、critical 标志及 DER 字节。
//
// Extensions returns every extension of the CRL in their original order.
//
// The result is nil for a nil or closed CRL. Each entry contains the
// extension NID, short name, critical flag and DER bytes.
func (c *CRL) Extensions() []Extension {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	count := native.X509_CRL_get_ext_count(c.handle.Ptr())
	out := make([]Extension, 0, count)
	for i := 0; i < count; i++ {
		e := native.X509_CRL_get_ext(c.handle.Ptr(), i)
		if e == nil {
			continue
		}
		nid := native.OBJ_obj2nid(native.X509_EXTENSION_get_object(e))
		out = append(out, Extension{
			Nid:      nid,
			Field:    native.OBJ_nid2sn(nid),
			Critical: native.X509_EXTENSION_get_critical(e) != 0,
			Data:     native.ASN1_STRING_data_bytes(native.X509_EXTENSION_get_data(e)),
		})
	}
	return out
}

// Close 释放底层 X509_CRL 句柄。
//
// 调用是幂等的：对 nil 接收者或已关闭的 CRL 调用返回 nil，不产生副作用；Close 返回后，
// 其他方法对该 *CRL 调用将返回 "x509: CRL closed" 错误（查询类方法返回零值），
// 调用方须保证无并发 goroutine 仍持有该 CRL 的引用。
//
// Close releases the underlying X509_CRL handle.
//
// The call is idempotent: invoking it on a nil receiver or on a CRL
// that has already been closed returns nil without further side
// effects. After Close returns, any other method on the same *CRL
// returns the error "x509: CRL closed" (or a zero-value result for
// query-style methods), so the caller must guarantee that no concurrent
// goroutine still holds a reference to this CRL.
func (c *CRL) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// RevocationCheck 检查证书是否被任何 CRL 吊销。
//
// 仅当某张 CRL 的签发者名字（X509_NAME_cmp 返回 0）与证书签发者一致且包含相同序列号的条目时判定为已吊销；未吊销返回 nil；已吊销返回含吊销原因的描述性错误（CRL 省略 reason 时默认 "unspecified"）；cert 必须是未关闭的有效 *Certificate，切片中的 nil 或已关闭 CRL 会被静默跳过。
//
// RevocationCheck checks whether the certificate has been revoked by any
// of the supplied CRLs.
//
// A certificate is considered revoked only when a CRL shares its issuer
// name (X509_NAME_cmp returns 0) and contains an entry with the same
// serial number. Returns nil when the certificate is not revoked, and
// a descriptive error when it is, including the revocation reason
// (defaulting to "unspecified" when the CRL omits one). cert must be a
// live, non-closed *Certificate; nil or closed CRLs in the slice are
// silently skipped.
func RevocationCheck(cert *Certificate, crls []*CRL) error {
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return fmt.Errorf("x509: invalid certificate")
	}
	serial := cert.Serial()
	certIssuer := native.X509_get_issuer_name(cert.handle.Ptr())
	for _, crl := range crls {
		if crl == nil || crl.handle == nil || crl.handle.IsClosed() {
			continue
		}
		crlIssuer := native.X509_CRL_get_issuer(crl.handle.Ptr())
		if native.X509_NAME_cmp(certIssuer, crlIssuer) != 0 {
			continue // 签发者不匹配
		}
		for _, e := range crl.RevokedEntries() {
			if e.Serial != serial {
				continue
			}
			reason := e.Reason
			if reason == "" {
				reason = "unspecified"
			}
			return fmt.Errorf("x509: certificate with serial %d is revoked (reason: %s)",
				serial, reason)
		}
	}
	return nil
}
