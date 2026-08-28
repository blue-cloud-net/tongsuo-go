// Package asn1 提供 DER 编码解析为可读树（tag / len / value + hex dump）。
//
// 纯 Go 实现，不依赖铜锁，可用于调试证书/密钥/签名等 DER 结构。
package asn1

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ASN.1 类常量。
const (
	ClassUniversal       = 0
	ClassApplication     = 1
	ClassContextSpecific = 2
	ClassPrivate         = 3
)

// Universal tag 编号。
const (
	TagBoolean         = 1
	TagInteger         = 2
	TagBitString       = 3
	TagOctetString     = 4
	TagNull            = 5
	TagOID             = 6
	TagUTF8String      = 12
	TagSequence        = 16
	TagSet             = 17
	TagPrintableString = 19
	TagT61String       = 20
	TagIA5String       = 22
	TagUTCTime         = 23
	TagGeneralizedTime = 24
)

// Node 表示 DER 中的一个 TLV 节点。
type Node struct {
	Offset      int    // 起始偏移
	Tag         byte   // 首个 tag 字节
	Class       int    // 类（Class* 常量）
	Number      int    // tag 编号
	Constructed bool   // 是否构造类型
	Length      int    // value 长度
	Value       []byte // 原始 value 字节
	Children    []*Node
}

// Parse 解析 DER 编码为树。
func Parse(der []byte) (*Node, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("asn1: empty DER")
	}
	n, used, err := parseNode(der, 0)
	if err != nil {
		return nil, err
	}
	if used != len(der) {
		return nil, fmt.Errorf("asn1: %d trailing bytes after top-level value", len(der)-used)
	}
	return n, nil
}

// parseNode 解析一个 TLV 节点，返回节点与消费的字节数。
func parseNode(der []byte, base int) (*Node, int, error) {
	if len(der) == 0 {
		return nil, 0, fmt.Errorf("asn1: truncated")
	}
	start := base // 绝对偏移（用于 Node.Offset）
	tagByte := der[0]
	off := 1
	class := int(tagByte >> 6)
	constructed := tagByte&0x20 != 0
	number := int(tagByte & 0x1f)
	if number == 0x1f { // 高 tag 编号（base-128 大端）
		number = 0
		for {
			if off >= len(der) {
				return nil, 0, fmt.Errorf("asn1: truncated tag")
			}
			b := der[off]
			off++
			number = number*128 + int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	length, nLen, err := parseLength(der[off:])
	if err != nil {
		return nil, 0, err
	}
	off += nLen
	if length < 0 || off+length > len(der) {
		return nil, 0, fmt.Errorf("asn1: bad length %d at offset %d", length, start)
	}
	value := der[off : off+length]
	node := &Node{
		Offset: start, Tag: tagByte, Class: class, Number: number,
		Constructed: constructed, Length: length, Value: value,
	}
	if constructed {
		cur := off
		for cur < off+length {
			child, used, err := parseNode(value[cur-off:], start+cur)
			if err != nil {
				return nil, 0, err
			}
			node.Children = append(node.Children, child)
			cur += used
		}
	}
	return node, off + length, nil // used 为相对 der 子切片的消费字节数
}

// parseLength 解析长度字节，返回长度与消耗字节数。
func parseLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("asn1: truncated length")
	}
	first := b[0]
	if first&0x80 == 0 {
		return int(first), 1, nil
	}
	n := int(first & 0x7f)
	if n == 0 {
		return 0, 0, fmt.Errorf("asn1: indefinite length not allowed in DER")
	}
	if n > 4 || 1+n > len(b) {
		return 0, 0, fmt.Errorf("asn1: bad long-form length")
	}
	length := 0
	for i := 0; i < n; i++ {
		length = length*256 + int(b[1+i])
	}
	return length, 1 + n, nil
}

// classStr 返回类名。
func classStr(c int) string {
	switch c {
	case ClassUniversal:
		return "UNIVERSAL"
	case ClassApplication:
		return "APPLICATION"
	case ClassContextSpecific:
		return "CONTEXT"
	default:
		return "PRIVATE"
	}
}

// tagName 返回 tag 的通用名称（Universal 类）或 "tag:n"。
func tagName(n *Node) string {
	if n.Class != ClassUniversal {
		return fmt.Sprintf("tag:%d", n.Number)
	}
	switch n.Number {
	case TagBoolean:
		return "BOOLEAN"
	case TagInteger:
		return "INTEGER"
	case TagBitString:
		return "BIT STRING"
	case TagOctetString:
		return "OCTET STRING"
	case TagNull:
		return "NULL"
	case TagOID:
		return "OBJECT IDENTIFIER"
	case TagUTF8String:
		return "UTF8String"
	case TagSequence:
		return "SEQUENCE"
	case TagSet:
		return "SET"
	case TagPrintableString:
		return "PrintableString"
	case TagT61String:
		return "T61String"
	case TagIA5String:
		return "IA5String"
	case TagUTCTime:
		return "UTCTime"
	case TagGeneralizedTime:
		return "GeneralizedTime"
	default:
		return fmt.Sprintf("tag:%d", n.Number)
	}
}

// Dump 返回 DER 树的可读文本（含 hex dump）。
func Dump(n *Node) string {
	var sb strings.Builder
	dumpNode(&sb, n, 0)
	return sb.String()
}

func dumpNode(sb *strings.Builder, n *Node, depth int) {
	indent := strings.Repeat("  ", depth)
	sb.WriteString(fmt.Sprintf("%soffset=%d %s %s len=%d\n",
		indent, n.Offset, tagName(n), classStr(n.Class), n.Length))
	if len(n.Children) > 0 {
		for _, c := range n.Children {
			dumpNode(sb, c, depth+1)
		}
		return
	}
	if len(n.Value) > 0 {
		sb.WriteString(hexDump(n.Value, depth+1))
	}
}

// hexDump 输出 value 的十六进制转储（每行 16 字节）。
func hexDump(b []byte, depth int) string {
	indent := strings.Repeat("  ", depth)
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]
		hexStr := hex.EncodeToString(chunk)
		// 每两个字节一组
		var groups []string
		for j := 0; j < len(hexStr); j += 4 {
			g := hexStr[j:]
			if len(g) > 4 {
				g = g[:4]
			}
			groups = append(groups, g)
		}
		ascii := printable(chunk)
		sb.WriteString(fmt.Sprintf("%s%04x: %-50s %s\n", indent, i, strings.Join(groups, " "), ascii))
	}
	return sb.String()
}

// printable 将字节转为可打印 ASCII 字符串。
func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
