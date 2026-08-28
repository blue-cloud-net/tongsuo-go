package core

import (
	"encoding/hex"
	"fmt"
	"time"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

// NameEntry 表示 X.509 名字中的一个 RDN 条目。
type NameEntry struct {
	Nid   int    // 字段 NID（如 native.NidCommonName）
	Field string // 字段短名（如 "CN"、"O"）
	Value string // 字段值（UTF-8）
}

// Name 表示 X.509 名字（X509_NAME 的包装），用于构建证书主题/签发者。
type Name struct {
	handle *Handle
}

// NewName 创建空名字。
func NewName() (*Name, error) {
	n := native.X509_NAME_new()
	if n == nil {
		return nil, NewOpError("x509: X509_NAME_new", native.PopError())
	}
	return &Name{handle: NewHandle(n, true, native.X509_NAME_free)}, nil
}

// AddEntry 添加名字条目。field 取 "CN"、"C"、"O"、"OU"、"L"、"ST"、"serialNumber"、"emailAddress" 等。
func (n *Name) AddEntry(field, value string) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: name closed")
	}
	if !native.X509_NAME_add_entry_by_txt(n.handle.Ptr(), field, value) {
		return NewOpError("x509: X509_NAME_add_entry_by_txt", native.PopError())
	}
	return nil
}

// Text 返回名字中指定 NID 字段的文本（如 native.NidCommonName）。
func (n *Name) Text(nid int) string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	return native.X509_NAME_get_text_by_NID(n.handle.Ptr(), nid)
}

// Get 返回名字中指定字段短名（如 "CN"、"O"）的文本；未找到返回空串。
func (n *Name) Get(field string) string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	return native.X509_NAME_get_text_by_txt(n.handle.Ptr(), field)
}

// Entries 返回名字的全部 RDN 条目（保持证书中的顺序）。
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

// String 返回名字的完整单行文本（如 "/CN=example.com/O=Example Org"）。
func (n *Name) String() string {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return ""
	}
	s, _ := native.X509_NAME_oneline(n.handle.Ptr())
	return s
}

// Close 释放底层名字。幂等。
func (n *Name) Close() error {
	if n == nil {
		return nil
	}
	return n.handle.Close()
}

// Certificate 表示一张 X.509 证书（X509 的包装）。
type Certificate struct {
	handle *Handle
}

// NewCertificate 创建空的证书对象。
func NewCertificate() (*Certificate, error) {
	x := native.X509_new()
	if x == nil {
		return nil, NewOpError("x509: X509_new", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// LoadCertificatePEM 从 PEM 加载证书。
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

// LoadCertificateDER 从 DER 编码加载证书。
func LoadCertificateDER(der []byte) (*Certificate, error) {
	x := native.D2i_X509(der)
	if x == nil {
		return nil, NewOpError("x509: d2i_X509", native.PopError())
	}
	return &Certificate{handle: NewHandle(x, true, native.X509_free)}, nil
}

// MarshalPEM 导出证书为 PEM。
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

// SetVersion 设置证书版本（0=v1，2=v3）。
func (c *Certificate) SetVersion(version int) error {
	if !native.X509_set_version(c.handle.Ptr(), version) {
		return NewOpError("x509: X509_set_version", native.PopError())
	}
	return nil
}

// SetSerial 设置证书序列号。
func (c *Certificate) SetSerial(serial int64) error {
	if !native.X509_set_serial_int(c.handle.Ptr(), serial) {
		return NewOpError("x509: X509_set_serialNumber", native.PopError())
	}
	return nil
}

// SetIssuer 设置签发者名字。
func (c *Certificate) SetIssuer(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid issuer name")
	}
	if !native.X509_set_issuer_name(c.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_set_issuer_name", native.PopError())
	}
	return nil
}

// SetSubject 设置主题名字。
func (c *Certificate) SetSubject(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid subject name")
	}
	if !native.X509_set_subject_name(c.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_set_subject_name", native.PopError())
	}
	return nil
}

// SetPublicKey 设置证书公钥。
func (c *Certificate) SetPublicKey(k *PKey) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_set_pubkey(c.handle.Ptr(), k.handle.Ptr()) {
		return NewOpError("x509: X509_set_pubkey", native.PopError())
	}
	return nil
}

// SetValidity 设置有效期（生效/过期时间）。
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

// AddBasicConstraints 添加 BasicConstraints 扩展（必须在 Sign 之前调用）。
// isCA 为 true 时标记为 CA 证书（critical,CA:TRUE）。
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

// Sign 使用签名私钥与摘要算法对证书签名（自签时签名密钥与公钥对应，CA 签发时用 CA 私钥）。
// md 传 nil 时按签名密钥类型自动选择（SM2→SM3，RSA/ECDSA→SHA256）。
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
func (c *Certificate) Verify(pub *PKey) error {
	if pub == nil || pub.handle == nil || pub.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_verify(c.handle.Ptr(), pub.handle.Ptr()) {
		return NewOpError("x509: X509_verify", native.PopError())
	}
	return nil
}

// SubjectName 返回主题名字（内部指针，勿关闭）。
func (c *Certificate) SubjectName() *Name {
	n := native.X509_get_subject_name(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// IssuerName 返回签发者名字（内部指针，勿关闭）。
func (c *Certificate) IssuerName() *Name {
	n := native.X509_get_issuer_name(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// Subject 返回主题的 CN（Common Name）。
func (c *Certificate) Subject() string {
	n := c.SubjectName()
	if n == nil {
		return ""
	}
	return n.Text(native.NidCommonName)
}

// Issuer 返回签发者的 CN（Common Name）。
func (c *Certificate) Issuer() string {
	n := c.IssuerName()
	if n == nil {
		return ""
	}
	return n.Text(native.NidCommonName)
}

// NotBefore 返回生效时间。
func (c *Certificate) NotBefore() time.Time {
	return time.Unix(native.X509_get_not_before(c.handle.Ptr()), 0).UTC()
}

// NotAfter 返回过期时间。
func (c *Certificate) NotAfter() time.Time {
	return time.Unix(native.X509_get_not_after(c.handle.Ptr()), 0).UTC()
}

// Serial 返回证书序列号。
func (c *Certificate) Serial() int64 {
	return native.X509_get_serial_int(c.handle.Ptr())
}

// Version 返回证书版本（0=v1，1=v2，2=v3）。
func (c *Certificate) Version() int {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return 0
	}
	return native.X509_get_version(c.handle.Ptr())
}

// SubjectEntries 返回主题完整 RDN 条目。
func (c *Certificate) SubjectEntries() []NameEntry {
	n := c.SubjectName()
	if n == nil {
		return nil
	}
	return n.Entries()
}

// IssuerEntries 返回签发者完整 RDN 条目。
func (c *Certificate) IssuerEntries() []NameEntry {
	n := c.IssuerName()
	if n == nil {
		return nil
	}
	return n.Entries()
}

// SubjectText 返回主题完整 RDN 单行文本。
func (c *Certificate) SubjectText() string {
	n := c.SubjectName()
	if n == nil {
		return ""
	}
	return n.String()
}

// IssuerText 返回签发者完整 RDN 单行文本。
func (c *Certificate) IssuerText() string {
	n := c.IssuerName()
	if n == nil {
		return ""
	}
	return n.String()
}

// SAN 返回证书 SAN（subjectAltName）扩展条目（如 "DNS:example.com"、"IP:1.2.3.4"）；
// 无 SAN 扩展返回 nil。
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

// KeyUsage 返回证书 KeyUsage 扩展的能力位名称列表（如 ["digitalSignature"]）；
// 无 KeyUsage 扩展返回 nil。
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

// ExtendedKeyUsage 返回证书 EKU（extendedKeyUsage）扩展条目（如 ["serverAuth"]）；
// 无 EKU 扩展返回 nil。
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

// PathLen 返回 CA 路径长度约束；无 pathlen 约束或非 CA 返回 -1。
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
func (c *Certificate) SubjectKeyID() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	return native.X509_get0_subject_key_id(c.handle.Ptr())
}

// AuthorityKeyID 返回 authorityKeyIdentifier 扩展中 keyid 的字节；无则返回 nil。
func (c *Certificate) AuthorityKeyID() []byte {
	if c == nil || c.handle == nil || c.handle.IsClosed() {
		return nil
	}
	return native.X509_get0_authority_key_id(c.handle.Ptr())
}

// CertificateType 返回证书公钥算法名（如 "SM2"、"RSA"、"EC"）。
func (c *Certificate) CertificateType() string {
	k, err := c.PublicKey()
	if err != nil {
		return ""
	}
	defer k.Close()
	return k.Algorithm()
}

// Fingerprint 计算证书指纹（十六进制小写）。md 传 core.SHA1() / core.SHA256() 等。
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
type Extension struct {
	Nid      int    // 扩展 NID（如 native.NidSubjectAltName）
	Field    string // 扩展短名（读取时填充，如 "subjectAltName"）
	Critical bool   // critical 标志（读取时填充）
	Value    string // X509V3_EXT_conf 配置串（构建时使用，如 "DNS:example.com"）
	Data     []byte // DER 编码的扩展值（读取时填充）
}

// Extensions 返回证书的全部扩展（按出现顺序）。
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

// AddExtension 添加一个通用扩展（必须在 Sign 之前调用）。
// nid 为扩展 NID；value 为 X509V3_EXT_conf 配置串（如 "DNS:example.com"，
// 可含 "critical," 前缀）。
func (c *Certificate) AddExtension(nid int, value string) error {
	return c.addExtCtx(c, nil, nid, value)
}

// AddSubjectAltName 添加 SAN 扩展（如 "DNS:example.com,IP:1.2.3.4"）。
func (c *Certificate) AddSubjectAltName(value string) error {
	return c.AddExtension(native.NidSubjectAltName, value)
}

// AddKeyUsage 添加 KeyUsage 扩展（如 "critical,digitalSignature,keyEncipherment"）。
func (c *Certificate) AddKeyUsage(value string) error {
	return c.AddExtension(native.NidKeyUsage, value)
}

// AddExtendedKeyUsage 添加 EKU 扩展（如 "serverAuth,clientAuth"）。
func (c *Certificate) AddExtendedKeyUsage(value string) error {
	return c.AddExtension(native.NidExtKeyUsage, value)
}

// AddSubjectKeyID 添加 SKID 扩展（值为 "hash"，按主题公钥计算）。
func (c *Certificate) AddSubjectKeyID() error {
	return c.addExtCtx(c, nil, native.NidSubjectKeyIdentifier, "hash")
}

// AddAuthorityKeyID 添加 AKID 扩展（keyid 取自 issuer 证书的 SKID 或按 issuer 公钥计算）。
// 须先为 issuer 完成公钥设置（含 AddSubjectKeyID 更佳）。
func (c *Certificate) AddAuthorityKeyID(issuer *Certificate) error {
	if issuer == nil || issuer.handle == nil || issuer.handle.IsClosed() {
		return fmt.Errorf("x509: invalid issuer certificate")
	}
	return c.addExtCtx(c, issuer, native.NidAuthorityKeyIdentifier, "keyid:always")
}

// addExtCtx 带 X509V3_CTX 创建扩展并追加（subject 用于 SKID，issuer 用于 AKID）。
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

// MarshalDER 导出证书为 DER 编码。
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

// PublicKey 返回证书公钥（新引用，调用方负责释放）。
func (c *Certificate) PublicKey() (*PKey, error) {
	p := native.X509_get_pubkey(c.handle.Ptr())
	if p == nil {
		return nil, NewOpError("x509: X509_get_pubkey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Close 释放底层证书。幂等。
func (c *Certificate) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// CertificateRequest 表示一个证书签名请求（X509_REQ 的包装）。
type CertificateRequest struct {
	handle *Handle
}

// NewCertificateRequest 创建空的 CSR。
func NewCertificateRequest() (*CertificateRequest, error) {
	r := native.X509_REQ_new()
	if r == nil {
		return nil, NewOpError("x509: X509_REQ_new", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// LoadCertificateRequestPEM 从 PEM 加载 CSR。
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

// LoadCertificateRequestDER 从 DER 编码加载 CSR。
func LoadCertificateRequestDER(der []byte) (*CertificateRequest, error) {
	r := native.D2i_X509_REQ(der)
	if r == nil {
		return nil, NewOpError("x509: d2i_X509_REQ", native.PopError())
	}
	return &CertificateRequest{handle: NewHandle(r, true, native.X509_REQ_free)}, nil
}

// MarshalPEM 导出 CSR 为 PEM。
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

// SetSubject 设置 CSR 主题。
func (r *CertificateRequest) SetSubject(n *Name) error {
	if n == nil || n.handle == nil || n.handle.IsClosed() {
		return fmt.Errorf("x509: invalid subject name")
	}
	if !native.X509_REQ_set_subject_name(r.handle.Ptr(), n.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_set_subject_name", native.PopError())
	}
	return nil
}

// SubjectName 返回 CSR 主题（内部指针，勿关闭）。
func (r *CertificateRequest) SubjectName() *Name {
	n := native.X509_REQ_get_subject_name(r.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// SetChallengePassword 设置 CSR 挑战密码（PKCS#9 challengePassword 属性，须在 Sign 之前调用）。
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
func (r *CertificateRequest) ChallengePassword() string {
	if r == nil || r.handle == nil || r.handle.IsClosed() {
		return ""
	}
	return native.X509_REQ_get_challenge_password(r.handle.Ptr())
}

// AddExtensions 为 CSR 添加多个扩展（如 SAN / KeyUsage / EKU，须在 Sign 之前调用）。
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

// AddExtension 为 CSR 添加单个扩展（须在 Sign 之前调用）。
func (r *CertificateRequest) AddExtension(nid int, value string) error {
	return r.AddExtensions(Extension{Nid: nid, Value: value})
}

// AddSubjectAltName 为 CSR 添加 SAN 扩展（如 "DNS:example.com"）。
func (r *CertificateRequest) AddSubjectAltName(value string) error {
	return r.AddExtension(native.NidSubjectAltName, value)
}

// Extensions 返回 CSR 中的扩展列表（来自 extensionRequest 属性）。
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

// MarshalDER 导出 CSR 为 DER 编码。
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

// SetPublicKey 设置 CSR 公钥。
func (r *CertificateRequest) SetPublicKey(k *PKey) error {
	if k == nil || k.handle == nil || k.handle.IsClosed() {
		return fmt.Errorf("x509: invalid public key")
	}
	if !native.X509_REQ_set_pubkey(r.handle.Ptr(), k.handle.Ptr()) {
		return NewOpError("x509: X509_REQ_set_pubkey", native.PopError())
	}
	return nil
}

// Sign 使用请求者私钥对 CSR 签名。md 传 nil 时按密钥类型自动选择。
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

// PublicKey 返回 CSR 公钥（新引用，调用方负责释放）。
func (r *CertificateRequest) PublicKey() (*PKey, error) {
	p := native.X509_REQ_get_pubkey(r.handle.Ptr())
	if p == nil {
		return nil, NewOpError("x509: X509_REQ_get_pubkey", native.PopError())
	}
	return &PKey{handle: NewHandle(p, true, native.EVP_PKEY_free)}, nil
}

// Close 释放底层 CSR。幂等。
func (r *CertificateRequest) Close() error {
	if r == nil {
		return nil
	}
	return r.handle.Close()
}

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

// VerifyError 表示证书链验证失败详情。
type VerifyError struct {
	Code    int    // X509_V_ERR_* 错误码（如 native.X509VErrCertHasExpired）
	Depth   int    // 出错深度（0 为待验证证书本身）
	Message string // 错误描述
}

// Error 实现 error 接口。
func (e *VerifyError) Error() string {
	if e == nil {
		return "x509: verify error"
	}
	return fmt.Sprintf("x509: certificate verify failed: %s (code=%d, depth=%d)",
		e.Message, e.Code, e.Depth)
}

// Store 表示证书信任存储（X509_STORE 的包装），作为 ChainVerify 的信任锚。
type Store struct {
	handle *Handle
}

// NewStore 创建空的信任存储。
func NewStore() (*Store, error) {
	s := native.X509_STORE_new()
	if s == nil {
		return nil, NewOpError("x509: X509_STORE_new", native.PopError())
	}
	return &Store{handle: NewHandle(s, true, native.X509_STORE_free)}, nil
}

// AddCert 向存储添加信任证书。
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

// AddCRL 向存储添加 CRL（配合 SetFlags(X509VFlagCRLCheck*) 启用吊销检查）。
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

// SetFlags 设置验证标志（如 native.X509VFlagCRLCheck / X509VFlagCRLCheckAll）。
func (s *Store) SetFlags(flags uint64) error {
	if s == nil || s.handle == nil || s.handle.IsClosed() {
		return fmt.Errorf("x509: store closed")
	}
	if !native.X509_STORE_set_flags(s.handle.Ptr(), flags) {
		return NewOpError("x509: X509_STORE_set_flags", native.PopError())
	}
	return nil
}

// Close 释放信任存储。幂等。
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.handle.Close()
}

// ChainVerify 验证证书链并返回构建的完整链（索引 0 为叶证书，末位为根）。
// store 为信任锚（Root CA）；intermediates 为中间证书（用于补全链）。
// 验证失败返回 *VerifyError。
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
type RevokedEntry struct {
	Serial         int64
	RevocationDate time.Time
	ReasonCode     int    // -1 表示未指定
	Reason         string // 原因名（如 "keyCompromise"）
}

// CRL 表示证书吊销列表（X509_CRL 的包装）。
type CRL struct {
	handle *Handle
}

// LoadCRLPEM 从 PEM 加载 CRL。
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

// LoadCRLDER 从 DER 加载 CRL。
func LoadCRLDER(der []byte) (*CRL, error) {
	c := native.D2i_X509_CRL(der)
	if c == nil {
		return nil, NewOpError("x509: d2i_X509_CRL", native.PopError())
	}
	return &CRL{handle: NewHandle(c, true, native.X509_CRL_free)}, nil
}

// MarshalPEM 导出 CRL 为 PEM。
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

// MarshalDER 导出 CRL 为 DER。
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

// Issuer 返回 CRL 签发者名字（内部指针，勿关闭）。
func (c *CRL) Issuer() *Name {
	n := native.X509_CRL_get_issuer(c.handle.Ptr())
	if n == nil {
		return nil
	}
	return &Name{handle: NewHandle(n, false, nil)}
}

// Version 返回 CRL 版本字段值（0=v1，1=v2）。
func (c *CRL) Version() int {
	return native.X509_CRL_get_version(c.handle.Ptr())
}

// LastUpdate 返回 CRL 生效时间。
func (c *CRL) LastUpdate() time.Time {
	return time.Unix(native.X509_CRL_get0_lastUpdate(c.handle.Ptr()), 0).UTC()
}

// NextUpdate 返回 CRL 过期时间。
func (c *CRL) NextUpdate() time.Time {
	return time.Unix(native.X509_CRL_get0_nextUpdate(c.handle.Ptr()), 0).UTC()
}

// RevokedEntries 返回 CRL 中的全部吊销记录。
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

// Close 释放 CRL。幂等。
func (c *CRL) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}

// RevocationCheck 检查证书是否被任何 CRL 吊销。
// 仅当 CRL 的签发者与证书签发者一致且序列号匹配时判定为已吊销。
// 未吊销返回 nil；已吊销返回描述性错误。
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
