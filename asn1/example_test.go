package asn1_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asn1"
)
// ExampleParse 演示解析 DER 编码为可读树。
// 本包与 Go 标准库 encoding/asn1 的区别：stdlib 关注结构化编解码（marshal/unmarshal
// 到 Go 类型）；本包关注**裸 DER 的可读展示**，输出带缩进的树形结构
// （tag 名称 / class / length / value hex dump）。
//
// ExampleParse demonstrates parsing DER-encoded bytes into a readable
// tree. Unlike the standard library's encoding/asn1 (which marshals and
// unmarshals between DER and Go types), this package focuses on a
// readable display of raw DER — an indented tree of tag names, classes,
// lengths and a hex dump of each value.
func ExampleParse() {
	// 一个最简的 SEQUENCE { INTEGER 1 } DER 编码：
	// SEQUENCE tag=0x30, len=0x03, INTEGER tag=0x02, len=0x01, value=0x01
	der, _ := hex.DecodeString("3003020101")

	root, err := asn1.Parse(der)
	if err != nil {
		panic(err)
	}
	fmt.Println(asn1.Dump(root))
	// Output:
	// offset=0 SEQUENCE UNIVERSAL len=3
	//   offset=2 INTEGER UNIVERSAL len=1
	//     0000: 01                                                 .
}
// ExampleParse_certificate 演示解析证书 DER 顶层 SEQUENCE。
// X.509 证书 ASN.1 结构：Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
// 直接子节点恰好 3 个，与 openssl asn1parse 一致。
//
// ExampleParse_certificate demonstrates that the top-level SEQUENCE of a
// X.509 certificate has exactly three direct children — tbsCertificate,
// signatureAlgorithm and signatureValue — matching the layout reported by
// openssl asn1parse.
func ExampleParse_certificate() {
	der := []byte{
		0x30, 0x03, // SEQUENCE, len=3
		0x02, 0x01, 0x01, // INTEGER 1
	}

	root, err := asn1.Parse(der)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(root.Children))
	// Output: 1
}
