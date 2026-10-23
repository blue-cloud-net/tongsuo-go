package x509

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// certificatePolicies 扩展（RFC 5280 §4.2.1.4）的 DER 编解码。
//
// 本文件是纯 Go 实现，不依赖铜锁，因此可以脱离 cgo 单独测试。
//
// DER encoding and decoding for the certificatePolicies extension
// (RFC 5280 §4.2.1.4).
//
// This file is a pure Go implementation and does not depend on the Tongsuo
// native library, so it can be tested without cgo.

// certificatePolicies 相关的 ASN.1 tag。
//
// ASN.1 tags used by the certificatePolicies structures.
const (
	derTagInteger    = 0x02
	derTagOID        = 0x06
	derTagUTF8String = 0x0c
	derTagIA5String  = 0x16
	derTagSequence   = 0x30
	derTagVisibleStr = 0x1a
	derTagBMPString  = 0x1e
)

// 策略限定符的 OID 内容字节（不含 tag 与长度）。
//
// id-qt-cps = 1.3.6.1.5.5.7.2.1，id-qt-unotice = 1.3.6.1.5.5.7.2.2。
//
// The content bytes (without tag and length) of the policy qualifier OIDs.
//
// id-qt-cps is 1.3.6.1.5.5.7.2.1 and id-qt-unotice is 1.3.6.1.5.5.7.2.2.
var (
	oidCPSContent        = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01}
	oidUserNoticeContent = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02}
)

// errCertPol 前缀：certificatePolicies 相关的错误统一带此前缀，便于检索。
//
// errCertPol prefixes every certificatePolicies error so that callers can
// filter them out of a mixed error stream.
const errCertPol = "x509: certificatePolicies: "

// encodeCertificatePolicies 把策略列表编码为 certificatePolicies 扩展的 DER 值。
//
// 编码结构（RFC 5280 §4.2.1.4）：
//
//	CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
//	PolicyInformation ::= SEQUENCE {
//	     policyIdentifier   CertPolicyId,
//	     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
//	PolicyQualifierInfo ::= SEQUENCE {
//	     policyQualifierId  PolicyQualifierId,
//	     qualifier          ANY DEFINED BY policyQualifierId }
//
// 无限定符的策略**省略** policyQualifiers 整体（它带 SIZE (1..MAX) 约束，空
// SEQUENCE 非法）。
//
// encodeCertificatePolicies encodes the policy list into the DER value of the
// certificatePolicies extension.
//
// The encoding follows RFC 5280 §4.2.1.4. A policy without qualifiers omits
// the policyQualifiers field entirely, because that field carries a
// SIZE (1..MAX) constraint and an empty SEQUENCE would be illegal.
func encodeCertificatePolicies(policies []CertificatePolicy) ([]byte, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("%sno policy given", errCertPol)
	}
	seen := make(map[string]bool, len(policies))
	var body []byte
	for i, p := range policies {
		if seen[p.OID] {
			return nil, fmt.Errorf("%sduplicate policy OID %q", errCertPol, p.OID)
		}
		seen[p.OID] = true
		oidContent, err := encodeOID(p.OID)
		if err != nil {
			return nil, fmt.Errorf("%spolicy %d: %w", errCertPol, i, err)
		}
		oid := derTLV(derTagOID, oidContent)
		qualifiers, err := encodePolicyQualifiers(p)
		if err != nil {
			return nil, fmt.Errorf("%spolicy %d: %w", errCertPol, i, err)
		}
		body = append(body, derTLV(derTagSequence, append(oid, qualifiers...))...)
	}
	return derTLV(derTagSequence, body), nil
}

// encodePolicyQualifiers 编码一条策略的 policyQualifiers 字段。
//
// 该字段是 OPTIONAL，因此没有限定符时返回 nil（调用方据此省略整个字段）。
// 同一条策略可以带多条 CPS 限定符与至多一条 userNotice 限定符，CPS 排在前面。
//
// encodePolicyQualifiers encodes the policyQualifiers field of one policy.
//
// The field is OPTIONAL, so nil is returned when the policy carries no
// qualifier and the caller omits the field entirely. A single policy may
// carry several CPS qualifiers and at most one userNotice qualifier; the CPS
// qualifiers come first.
func encodePolicyQualifiers(p CertificatePolicy) ([]byte, error) {
	var quals []byte
	for _, uri := range p.CPSURIs {
		if uri == "" {
			return nil, fmt.Errorf("empty CPS URI")
		}
		if !isIA5String(uri) {
			return nil, fmt.Errorf("CPS URI %q contains non-IA5 characters", uri)
		}
		inner := derTLV(derTagIA5String, []byte(uri))
		quals = append(quals, derTLV(derTagSequence,
			append(derTLV(derTagOID, oidCPSContent), inner...))...)
	}
	if p.UserNotice != nil {
		notice, err := encodeUserNotice(*p.UserNotice)
		if err != nil {
			return nil, err
		}
		inner := derTLV(derTagSequence, notice)
		quals = append(quals, derTLV(derTagSequence,
			append(derTLV(derTagOID, oidUserNoticeContent), inner...))...)
	}
	if len(quals) == 0 {
		return nil, nil
	}
	return derTLV(derTagSequence, quals), nil
}

// encodeUserNotice 编码 UserNotice 结构的内容部分（不含外层 SEQUENCE）。
//
//	UserNotice ::= SEQUENCE {
//	     noticeRef        NoticeReference OPTIONAL,
//	     explicitText     DisplayText OPTIONAL }
//	NoticeReference ::= SEQUENCE {
//	     organization     DisplayText,
//	     noticeNumbers    SEQUENCE OF INTEGER }
//
// noticeRef 与 explicitText 均为 OPTIONAL，但 NoticeReference 内部的
// organization 是必填的——因此只给 noticeNumbers 而不给 organization 属于
// 非法配置，直接报错。
//
// DisplayText 以 UTF8String 编码（RFC 5280 的 CHOICE 允许 utf8String）。
// 铜锁 openssl 的配置文件路径用的是 VisibleString，对非 ASCII 内容会产出
// 不合规的 DER；本库统一用 UTF8String，铜锁可以正常读回。
//
// encodeUserNotice encodes the content of a UserNotice structure (without the
// enclosing SEQUENCE).
//
// Both noticeRef and explicitText are OPTIONAL, but organization inside
// NoticeReference is mandatory, so notice numbers without an organization are
// rejected as invalid configuration.
//
// DisplayText is encoded as UTF8String (the DisplayText CHOICE in RFC 5280
// permits utf8String). The Tongsuo openssl configuration path uses
// VisibleString instead, which produces non-conformant DER for non-ASCII
// content; this library always uses UTF8String, which Tongsuo reads back
// correctly.
func encodeUserNotice(n UserNotice) ([]byte, error) {
	if n.Organization == "" && len(n.NoticeNumbers) == 0 && n.ExplicitText == "" {
		return nil, fmt.Errorf("empty user notice")
	}
	if len(n.NoticeNumbers) > 0 && n.Organization == "" {
		return nil, fmt.Errorf("notice numbers require an organization")
	}
	var body []byte
	if n.Organization != "" {
		numbers := make([]byte, 0, len(n.NoticeNumbers))
		for _, num := range n.NoticeNumbers {
			numbers = append(numbers, derTLV(derTagInteger, encodeInteger(num))...)
		}
		ref := derTLV(derTagSequence, append(
			derTLV(derTagUTF8String, []byte(n.Organization)),
			derTLV(derTagSequence, numbers)...))
		body = append(body, ref...)
	}
	if n.ExplicitText != "" {
		body = append(body, derTLV(derTagUTF8String, []byte(n.ExplicitText))...)
	}
	return body, nil
}

// encodeInteger 按 DER 规则编码整数的最小补码表示。
//
// encodeInteger encodes an integer as its minimal two's complement form.
func encodeInteger(v int) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	if v > 0 {
		var b []byte
		for x := v; x > 0; x >>= 8 {
			b = append([]byte{byte(x & 0xff)}, b...)
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return b
	}
	// 负数：先取补码，再按位数截断。
	x := int64(v)
	var b []byte
	for i := 0; i < 8; i++ {
		b = append([]byte{byte(x & 0xff)}, b...)
		x >>= 8
	}
	// 去掉多余的高位 0xff / 0x00。
	for len(b) > 1 {
		if b[0] == 0x00 && b[1]&0x80 == 0 {
			b = b[1:]
			continue
		}
		if b[0] == 0xff && b[1]&0x80 != 0 {
			b = b[1:]
			continue
		}
		break
	}
	return b
}

// encodeOID 把点分 OID 文本编码为 ASN.1 OBJECT IDENTIFIER 的内容字节。
//
// 第一段与第二段合并为 40*arc0+arc1（arc0 为 0 / 1 时第二段不得大于 39），
// 其余各段按 base-128 变长编码。
//
// encodeOID encodes a dotted OID string into the content bytes of an ASN.1
// OBJECT IDENTIFIER.
//
// The first two arcs are combined into 40*arc0+arc1 (when arc0 is 0 or 1 the
// second arc must not exceed 39); the remaining arcs use base-128 variable
// length encoding.
func encodeOID(oid string) ([]byte, error) {
	oid = strings.TrimSpace(oid)
	if oid == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q: need at least two arcs", oid)
	}
	arcs := make([]uint64, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("invalid OID %q: empty arc", oid)
		}
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q: bad arc %q", oid, p)
		}
		arcs = append(arcs, v)
	}
	if arcs[0] > 2 {
		return nil, fmt.Errorf("invalid OID %q: first arc must be 0, 1 or 2", oid)
	}
	if arcs[0] < 2 && arcs[1] > 39 {
		return nil, fmt.Errorf("invalid OID %q: second arc must not exceed 39 when the first arc is 0 or 1", oid)
	}
	if arcs[0] == 2 && arcs[1] > math.MaxUint64/40 {
		return nil, fmt.Errorf("invalid OID %q: second arc too large", oid)
	}
	out := base128(arcs[0]*40 + arcs[1])
	for _, a := range arcs[2:] {
		out = append(out, base128(a)...)
	}
	return out, nil
}

// base128 按 base-128 变长规则编码一个非负整数（高位在前，最高位组置连续位 1）。
//
// base128 encodes a non-negative integer using the base-128 variable length
// form, most significant group first, with the high bit set on every group but
// the last.
func base128(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0x7f)}, b...)
		v >>= 7
	}
	for i := 0; i < len(b)-1; i++ {
		b[i] |= 0x80
	}
	return b
}

// derLen 按 DER 规则编码长度。
//
// derLen encodes a length using the DER length rules.
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for v := n; v > 0; v >>= 8 {
		tmp = append([]byte{byte(v & 0xff)}, tmp...)
	}
	out := make([]byte, 0, 1+len(tmp))
	out = append(out, byte(0x80|len(tmp)))
	return append(out, tmp...)
}

// derTLV 组装一个 tag / length / content 三元组。
//
// derTLV assembles a tag / length / content triple.
func derTLV(tag byte, content []byte) []byte {
	l := derLen(len(content))
	out := make([]byte, 0, 1+len(l)+len(content))
	out = append(out, tag)
	out = append(out, l...)
	return append(out, content...)
}

// isIA5String 判断字符串是否只含 IA5（7-bit ASCII）字符。
//
// IA5String 的字符集是 7-bit ASCII；CPS 限定符按 RFC 5280 必须是 IA5String，
// 因此超出该范围的字符无法编码。
//
// isIA5String reports whether s contains only IA5 (7-bit ASCII) characters.
//
// The IA5String character set is 7-bit ASCII. RFC 5280 requires the CPS
// qualifier to be an IA5String, so characters outside that range cannot be
// encoded.
func isIA5String(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

// derCursor 是按 schema 驱动的 DER 读取游标。
//
// 解析深度由 schema 固定（certificatePolicies 最多四层嵌套），因此不存在
// 递归解析深度失控的问题，无需额外的深度上限。
//
// derCursor is a schema-driven DER reading cursor.
//
// The parsing depth is fixed by the schema (certificatePolicies nests at most
// four levels), so there is no risk of unbounded recursion and no extra depth
// limit is needed.
type derCursor struct {
	data []byte
	pos  int
}

// empty 报告游标是否已读完。
//
// empty reports whether the cursor has consumed all its data.
func (c *derCursor) empty() bool { return c.pos >= len(c.data) }

// read 读取一个 TLV 元素，返回 tag 与内容字节。
//
// 不定长编码（indefinite length）在 DER 中非法，直接报错。
//
// read reads one TLV element and returns its tag and content bytes.
//
// Indefinite-length encoding is illegal in DER and is rejected.
func (c *derCursor) read() (byte, []byte, error) {
	if c.pos >= len(c.data) {
		return 0, nil, fmt.Errorf("truncated element")
	}
	tag := c.data[c.pos]
	c.pos++
	if c.pos >= len(c.data) {
		return 0, nil, fmt.Errorf("truncated length")
	}
	first := c.data[c.pos]
	c.pos++
	length := 0
	if first&0x80 == 0 {
		length = int(first)
	} else {
		n := int(first & 0x7f)
		if n == 0 {
			return 0, nil, fmt.Errorf("indefinite length is not allowed in DER")
		}
		if n > 4 {
			return 0, nil, fmt.Errorf("bad long-form length")
		}
		if c.pos+n > len(c.data) {
			return 0, nil, fmt.Errorf("truncated length")
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(c.data[c.pos+i])
		}
		c.pos += n
	}
	if length < 0 || c.pos+length > len(c.data) {
		return 0, nil, fmt.Errorf("truncated content")
	}
	content := c.data[c.pos : c.pos+length]
	c.pos += length
	return tag, content, nil
}

// parseCertificatePolicies 解析 certificatePolicies 扩展的 DER 值。
//
// 未知限定符 OID 被跳过（RFC 允许扩展限定符类型）；DisplayText 的四种
// CHOICE 分支（UTF8String / VisibleString / IA5String / BMPString）都被接受，
// 以便读取由铜锁 openssl 生成的证书——它用的是 VisibleString。
//
// 限定符的相对顺序在解析后被归一：同一策略的 CPS 限定符聚在一起排在
// userNotice 之前（编码时也是这个顺序）。
//
// parseCertificatePolicies parses the DER value of a certificatePolicies
// extension.
//
// Unknown qualifier OIDs are skipped (RFC 5280 allows extending the set of
// qualifiers). All four DisplayText CHOICE alternatives (UTF8String,
// VisibleString, IA5String and BMPString) are accepted so that certificates
// produced by the Tongsuo openssl command line — which uses VisibleString —
// can be read back.
//
// The relative order of the qualifiers is normalized by the parse: the CPS
// qualifiers of one policy are grouped together ahead of the userNotice (the
// encoder emits them in that order too).
func parseCertificatePolicies(der []byte) ([]CertificatePolicy, error) {
	cur := &derCursor{data: der}
	tag, body, err := cur.read()
	if err != nil {
		return nil, fmt.Errorf("%s%w", errCertPol, err)
	}
	if tag != derTagSequence {
		return nil, fmt.Errorf("%sexpected a SEQUENCE, got tag 0x%02x", errCertPol, tag)
	}
	if !cur.empty() {
		return nil, fmt.Errorf("%strailing bytes after the policy sequence", errCertPol)
	}
	policies := make([]CertificatePolicy, 0, 1)
	pc := &derCursor{data: body}
	for !pc.empty() {
		p, err := parsePolicyInformation(pc)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("%sthe policy sequence is empty", errCertPol)
	}
	return policies, nil
}

// parsePolicyInformation 解析一条 PolicyInformation。
//
// parsePolicyInformation parses one PolicyInformation entry.
func parsePolicyInformation(c *derCursor) (CertificatePolicy, error) {
	var p CertificatePolicy
	tag, body, err := c.read()
	if err != nil {
		return p, fmt.Errorf("%spolicy information: %w", errCertPol, err)
	}
	if tag != derTagSequence {
		return p, fmt.Errorf("%spolicy information must be a SEQUENCE, got tag 0x%02x", errCertPol, tag)
	}
	inner := &derCursor{data: body}
	tag, oidBytes, err := inner.read()
	if err != nil {
		return p, fmt.Errorf("%spolicy identifier: %w", errCertPol, err)
	}
	if tag != derTagOID {
		return p, fmt.Errorf("%spolicy identifier must be an OBJECT IDENTIFIER, got tag 0x%02x", errCertPol, tag)
	}
	p.OID = decodeOID(oidBytes)
	if inner.empty() {
		return p, nil
	}
	tag, qualBody, err := inner.read()
	if err != nil {
		return p, fmt.Errorf("%spolicy qualifiers: %w", errCertPol, err)
	}
	if tag != derTagSequence {
		return p, fmt.Errorf("%spolicy qualifiers must be a SEQUENCE, got tag 0x%02x", errCertPol, tag)
	}
	if !inner.empty() {
		return p, fmt.Errorf("%strailing bytes in the policy information", errCertPol)
	}
	qc := &derCursor{data: qualBody}
	for !qc.empty() {
		if err := parsePolicyQualifier(qc, &p); err != nil {
			return p, err
		}
	}
	return p, nil
}

// parsePolicyQualifier 解析一条 PolicyQualifierInfo 并写入策略。
//
// 未知限定符 OID 被忽略（限定符内容已整体读出，无需再解析）。
//
// parsePolicyQualifier parses one PolicyQualifierInfo into the policy.
//
// An unknown qualifier OID is ignored — the qualifier content has already
// been read as a whole and needs no further parsing.
func parsePolicyQualifier(c *derCursor, p *CertificatePolicy) error {
	tag, body, err := c.read()
	if err != nil {
		return fmt.Errorf("%spolicy qualifier: %w", errCertPol, err)
	}
	if tag != derTagSequence {
		return fmt.Errorf("%spolicy qualifier must be a SEQUENCE, got tag 0x%02x", errCertPol, tag)
	}
	inner := &derCursor{data: body}
	tag, oidBytes, err := inner.read()
	if err != nil {
		return fmt.Errorf("%spolicy qualifier id: %w", errCertPol, err)
	}
	if tag != derTagOID {
		return fmt.Errorf("%spolicy qualifier id must be an OBJECT IDENTIFIER, got tag 0x%02x", errCertPol, tag)
	}
	switch {
	case string(oidBytes) == string(oidCPSContent):
		tag, cps, err := inner.read()
		if err != nil {
			return fmt.Errorf("%sCPS qualifier: %w", errCertPol, err)
		}
		if tag != derTagIA5String {
			return fmt.Errorf("%sCPS qualifier must be an IA5String, got tag 0x%02x", errCertPol, tag)
		}
		p.CPSURIs = append(p.CPSURIs, string(cps))
	case string(oidBytes) == string(oidUserNoticeContent):
		tag, notice, err := inner.read()
		if err != nil {
			return fmt.Errorf("%suser notice qualifier: %w", errCertPol, err)
		}
		if tag != derTagSequence {
			return fmt.Errorf("%suser notice must be a SEQUENCE, got tag 0x%02x", errCertPol, tag)
		}
		n, err := parseUserNotice(notice)
		if err != nil {
			return err
		}
		p.UserNotice = &n
	default:
		// 未知限定符类型：按 RFC 5280 忽略。
		return nil
	}
	if !inner.empty() {
		return fmt.Errorf("%strailing bytes in the policy qualifier", errCertPol)
	}
	return nil
}

// parseUserNotice 解析 UserNotice 的内容部分。
//
// parseUserNotice parses the content of a UserNotice structure.
func parseUserNotice(body []byte) (UserNotice, error) {
	var n UserNotice
	c := &derCursor{data: body}
	for !c.empty() {
		tag, content, err := c.read()
		if err != nil {
			return n, fmt.Errorf("%suser notice: %w", errCertPol, err)
		}
		switch tag {
		case derTagSequence:
			org, numbers, err := parseNoticeReference(content)
			if err != nil {
				return n, err
			}
			n.Organization = org
			n.NoticeNumbers = numbers
		case derTagUTF8String, derTagVisibleStr, derTagIA5String, derTagBMPString:
			text, err := decodeDisplayText(tag, content)
			if err != nil {
				return n, err
			}
			n.ExplicitText = text
		default:
			return n, fmt.Errorf("%sunexpected tag 0x%02x in the user notice", errCertPol, tag)
		}
	}
	return n, nil
}

// parseNoticeReference 解析 NoticeReference 的内容部分。
//
// body 是 NoticeReference 这个 SEQUENCE 的**内容**（已由调用方取出），
// 直接是 organization 与 noticeNumbers 两项。
//
// parseNoticeReference parses the content of a NoticeReference structure.
//
// body is the **content** of the NoticeReference SEQUENCE, already extracted
// by the caller; it holds the organization and the noticeNumbers directly.
func parseNoticeReference(body []byte) (string, []int, error) {
	c := &derCursor{data: body}
	tag, org, err := c.read()
	if err != nil {
		return "", nil, fmt.Errorf("%snotice reference organization: %w", errCertPol, err)
	}
	orgText, err := decodeDisplayText(tag, org)
	if err != nil {
		return "", nil, err
	}
	tag, numBody, err := c.read()
	if err != nil {
		return "", nil, fmt.Errorf("%snotice reference notice numbers: %w", errCertPol, err)
	}
	if tag != derTagSequence {
		return "", nil, fmt.Errorf("%snotice numbers must be a SEQUENCE, got tag 0x%02x", errCertPol, tag)
	}
	var numbers []int
	nc := &derCursor{data: numBody}
	for !nc.empty() {
		tag, numBytes, err := nc.read()
		if err != nil {
			return "", nil, fmt.Errorf("%snotice number: %w", errCertPol, err)
		}
		if tag != derTagInteger {
			return "", nil, fmt.Errorf("%snotice numbers must contain INTEGERs, got tag 0x%02x", errCertPol, tag)
		}
		n, err := decodeInteger(numBytes)
		if err != nil {
			return "", nil, fmt.Errorf("%snotice number: %w", errCertPol, err)
		}
		numbers = append(numbers, n)
	}
	return orgText, numbers, nil
}

// decodeDisplayText 按 DisplayText 的 CHOICE 分支解码文本。
//
// VisibleString 与 IA5String 按原始字节处理（铜锁 openssl 生成的证书用的是
// VisibleString，其内容可能是未校验的原始 UTF-8 字节，按原样保留才能还原
// 出原文）；BMPString 按 UTF-16BE 解码。
//
// decodeDisplayText decodes text according to the DisplayText CHOICE.
//
// VisibleString and IA5String are treated as raw bytes (certificates produced
// by the Tongsuo openssl command line use VisibleString whose content may be
// unchecked raw UTF-8 bytes; keeping them verbatim restores the original
// text). BMPString is decoded as UTF-16BE.
func decodeDisplayText(tag byte, content []byte) (string, error) {
	switch tag {
	case derTagUTF8String:
		return string(content), nil
	case derTagVisibleStr, derTagIA5String:
		return string(content), nil
	case derTagBMPString:
		if len(content)%2 != 0 {
			return "", fmt.Errorf("%sBMPString has an odd length", errCertPol)
		}
		units := make([]uint16, 0, len(content)/2)
		for i := 0; i+1 < len(content); i += 2 {
			units = append(units, uint16(content[i])<<8|uint16(content[i+1]))
		}
		return string(utf16.Decode(units)), nil
	default:
		return "", fmt.Errorf("%sunsupported DisplayText tag 0x%02x", errCertPol, tag)
	}
}

// decodeInteger 解析 DER 整数的补码表示。
//
// decodeInteger decodes the two's complement form of a DER integer.
func decodeInteger(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("empty INTEGER")
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("INTEGER exceeds 64 bits")
	}
	var u uint64
	for _, c := range b {
		u = u<<8 | uint64(c)
	}
	if b[0]&0x80 != 0 {
		// 负数：补码。长度为 8 时 u 本身已是完整的 64 位补码。
		if len(b) == 8 {
			return int(int64(u)), nil
		}
		return int(int64(u) - int64(1)<<(uint(8*len(b)))), nil
	}
	if u > math.MaxInt64 {
		return 0, fmt.Errorf("INTEGER out of range")
	}
	return int(u), nil
}

// decodeOID 把 ASN.1 OBJECT IDENTIFIER 的内容字节解码为点分文本。
//
// decodeOID decodes the content bytes of an ASN.1 OBJECT IDENTIFIER into
// dotted text.
func decodeOID(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	first, n, ok := readBase128(content)
	if !ok {
		return ""
	}
	var a, b uint64
	switch {
	case first < 40:
		a, b = 0, first
	case first < 80:
		a, b = 1, first-40
	default:
		a, b = 2, first-80
	}
	arcs := []uint64{a, b}
	rest := content[n:]
	for len(rest) > 0 {
		v, used, ok := readBase128(rest)
		if !ok {
			return ""
		}
		arcs = append(arcs, v)
		rest = rest[used:]
	}
	parts := make([]string, len(arcs))
	for i, v := range arcs {
		parts[i] = strconv.FormatUint(v, 10)
	}
	return strings.Join(parts, ".")
}

// readBase128 解析一个 base-128 变长整数，返回数值与消耗的字节数。
//
// readBase128 decodes one base-128 variable length integer and returns its
// value together with the number of bytes consumed.
func readBase128(b []byte) (uint64, int, bool) {
	var v uint64
	for i := 0; i < len(b); i++ {
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
		if v > math.MaxUint64>>7 {
			return 0, 0, false
		}
	}
	return 0, 0, false
}
