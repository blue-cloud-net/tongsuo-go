package meta

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Encoding 是字节的文本编码方式。
// 用于「输入源 → 字节」与「字节 → 输出汇」的统一维度，
// 对应铜锁 CLI 的 `-hex` / `-binary` / `-base64` 开关。
//
// Encoding is the textual encoding of byte strings. It provides the
// unified dimension between "input source to bytes" and "bytes to output
// sink", mirroring the Tongsuo CLI's -hex / -binary / -base64 switches.
//
// Encoding 的取值只允许本包定义的三个常量；解析用 ParseEncoding。
//
// The only valid Encoding values are the three constants defined by this
// package; use ParseEncoding to parse a textual form.
type Encoding string

const (
	// EncodingRaw 表示不做任何编码（原始字节）。
	//
	// EncodingRaw means no encoding at all (raw bytes).
	EncodingRaw Encoding = "raw"
	// EncodingHex 表示小写十六进制编码。
	//
	// EncodingHex means lower-case hexadecimal encoding.
	EncodingHex Encoding = "hex"
	// EncodingBase64 表示标准 base64 编码（含 "=" 填充）。
	//
	// EncodingBase64 means standard base64 encoding (with "=" padding).
	EncodingBase64 Encoding = "base64"
)

// ParseEncoding 解析编码名（大小写不敏感）。
// "raw" / "binary" / "none" 归一为 EncodingRaw；"hex" 归一为 EncodingHex；
// "base64" / "b64" 归一为 EncodingBase64。
// 未识别的名称返回错误。
//
// ParseEncoding parses an encoding name (case-insensitively). "raw",
// "binary" and "none" map to EncodingRaw; "hex" maps to EncodingHex;
// "base64" and "b64" map to EncodingBase64. An unrecognised name yields
// an error.
func ParseEncoding(s string) (Encoding, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "raw", "binary", "none", "":
		return EncodingRaw, nil
	case "hex", "hexdump":
		return EncodingHex, nil
	case "base64", "b64":
		return EncodingBase64, nil
	}
	return "", fmt.Errorf("meta: unknown encoding %q", s)
}

// Encode 按 enc 把 data 编码为文本。
// EncodingRaw 原样返回 data 的副本；未知编码返回错误。
//
// Encode encodes data as text according to enc. EncodingRaw returns a
// copy of data unchanged; an unknown encoding yields an error.
func Encode(data []byte, enc Encoding) ([]byte, error) {
	switch enc {
	case EncodingRaw:
		return append([]byte(nil), data...), nil
	case EncodingHex:
		out := make([]byte, hex.EncodedLen(len(data)))
		hex.Encode(out, data)
		return out, nil
	case EncodingBase64:
		out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(out, data)
		return out, nil
	}
	return nil, fmt.Errorf("meta: unknown encoding %q", string(enc))
}

// Decode 按 enc 把文本解码为字节。
// EncodingHex 接受大小写混合的十六进制并忽略空白；EncodingBase64 接受
// 标准 base64（含填充），忽略换行。未知编码或非法输入返回错误。
//
// Decode decodes text into bytes according to enc. EncodingHex accepts
// mixed-case hexadecimal and ignores whitespace; EncodingBase64 accepts
// standard padded base64 and ignores newlines. An unknown encoding or
// malformed input yields an error.
func Decode(data []byte, enc Encoding) ([]byte, error) {
	switch enc {
	case EncodingRaw:
		return append([]byte(nil), data...), nil
	case EncodingHex:
		s := strings.Map(func(r rune) rune {
			switch r {
			case ' ', '\t', '\r', '\n':
				return -1
			}
			return r
		}, string(data))
		out := make([]byte, hex.DecodedLen(len(s)))
		n, err := hex.Decode(out, []byte(s))
		if err != nil {
			return nil, fmt.Errorf("meta: hex decode: %w", err)
		}
		return out[:n], nil
	case EncodingBase64:
		s := strings.Map(func(r rune) rune {
			switch r {
			case '\r', '\n':
				return -1
			}
			return r
		}, string(data))
		out := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
		n, err := base64.StdEncoding.Decode(out, []byte(s))
		if err != nil {
			return nil, fmt.Errorf("meta: base64 decode: %w", err)
		}
		return out[:n], nil
	}
	return nil, fmt.Errorf("meta: unknown encoding %q", string(enc))
}

// Hex 返回 data 的小写十六进制表示。
//
// Hex returns the lower-case hexadecimal representation of data.
func Hex(data []byte) string {
	return hex.EncodeToString(data)
}

// Base64 返回 data 的标准 base64 表示（含填充）。
//
// Base64 returns the standard padded base64 representation of data.
func Base64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Dump 返回 data 的 hexdump 视图（对齐 `xxd` 的经典十六进制转储）。
// 每行 16 字节，右侧为可打印字符（不可打印字节以 "." 占位）。
// 空输入返回空串。
//
// Dump returns a hexdump view of data, aligned with the classic `xxd`
// hexadecimal dump: 16 bytes per line with a printable-character column
// on the right (non-printable bytes shown as "."). Empty input yields an
// empty string.
func Dump(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		b.WriteString(fmt.Sprintf("%08x  ", off))
		for i := 0; i < 16; i++ {
			if i == 8 {
				b.WriteByte(' ')
			}
			if i < len(chunk) {
				b.WriteString(fmt.Sprintf("%02x ", chunk[i]))
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" |")
		for _, c := range chunk {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|")
		if end < len(data) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
