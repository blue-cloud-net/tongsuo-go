package meta

import (
	"fmt"
	"strings"
)

// Format 是证书 / 密钥等对象的序列化格式。
// 用于「对象 ↔ 字节」的统一维度，对应铜锁 CLI 的 `-inform` / `-outform`。
//
// Format is the serialization format of objects such as certificates and
// keys. It provides the unified dimension between "object and bytes",
// mirroring the Tongsuo CLI's -inform / -outform switches.
//
// Format 的取值只允许本包定义的常量；解析用 ParseFormat。
//
// The only valid Format values are the constants defined by this package;
// use ParseFormat to parse a textual form.
type Format string

const (
	// FormatPEM 表示 PEM（Base64 文本 + 头部）编码。
	//
	// FormatPEM means PEM encoding (Base64 text with headers).
	FormatPEM Format = "PEM"
	// FormatDER 表示 DER（二进制）编码。
	//
	// FormatDER means DER (binary) encoding.
	FormatDER Format = "DER"
)

// ParseFormat 解析格式名（大小写不敏感）。
// "pem" 归一为 FormatPEM；"der" 归一为 FormatDER。
// 未识别的名称返回错误。
//
// ParseFormat parses a format name (case-insensitively). "pem" maps to
// FormatPEM and "der" maps to FormatDER. An unrecognised name yields an
// error.
func ParseFormat(s string) (Format, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PEM":
		return FormatPEM, nil
	case "DER":
		return FormatDER, nil
	}
	return "", fmt.Errorf("meta: unknown format %q", s)
}

// String 返回格式名的文本形式。
//
// String returns the textual form of the format name.
func (f Format) String() string {
	return string(f)
}
