package x509

import (
	"bytes"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// MarshalFormat 按 format 序列化证书：FormatPEM 返回 PEM 块，
// FormatDER 返回 DER 字节。未知格式返回错误。
//
// MarshalFormat serialises the certificate per format: FormatPEM yields
// a PEM block and FormatDER the DER bytes. An unknown format is an error.
func MarshalFormat(c *Certificate, format meta.Format) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("x509: nil certificate")
	}
	switch format {
	case meta.FormatPEM:
		return c.MarshalPEM()
	case meta.FormatDER:
		return c.MarshalDER()
	default:
		return nil, fmt.Errorf("x509: unsupported format %q", format)
	}
}

// LoadCertificateSource 从 src 读取证书，自动识别 PEM 与 DER 编码。
// src 为 nil 等价于标准输入。识别方式：内容（忽略前导空白）含 "-----BEGIN"
// 前缀按 PEM 解析（前导空白会被剔除），否则按 DER 解析。
//
// LoadCertificateSource reads a certificate from src, auto-detecting PEM
// versus DER. A nil src is equivalent to standard input. Content whose
// first non-blank bytes are "-----BEGIN" is parsed as PEM (the leading
// whitespace is trimmed), everything else as DER.
func LoadCertificateSource(src *meta.Source) (*Certificate, error) {
	blob, err := src.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("x509: empty certificate input")
	}
	if isPEMBlob(blob) {
		return LoadCertificatePEM(bytes.TrimLeft(blob, " \t\r\n"))
	}
	return LoadCertificateDER(blob)
}

// MarshalCertificateTo 按 format 序列化证书并按 sink 的编码写出。
// sink 为 nil 等价于标准输出；本函数不调用 sink.Close。
//
// MarshalCertificateTo serialises the certificate per format and writes
// it using sink's encoding. A nil sink means standard output; the
// function does not close sink.
func MarshalCertificateTo(c *Certificate, sink *meta.Sink, format meta.Format) error {
	blob, err := MarshalFormat(c, format)
	if err != nil {
		return err
	}
	if _, err := sink.Write(blob); err != nil {
		return fmt.Errorf("x509: write certificate: %w", err)
	}
	return nil
}

// MarshalCSRTo 按 format 序列化证书请求（PEM 或 DER）并按 sink 的编码写出。
// sink 为 nil 等价于标准输出；本函数不调用 sink.Close。
//
// MarshalCSRTo serialises the certificate request (PEM or DER) and
// writes it using sink's encoding. A nil sink means standard output; the
// function does not close sink.
func MarshalCSRTo(r *CertificateRequest, sink *meta.Sink, format meta.Format) error {
	if r == nil {
		return fmt.Errorf("x509: nil certificate request")
	}
	var (
		blob []byte
		err  error
	)
	switch format {
	case meta.FormatPEM:
		blob, err = r.MarshalPEM()
	case meta.FormatDER:
		blob, err = r.MarshalDER()
	default:
		return fmt.Errorf("x509: unsupported format %q", format)
	}
	if err != nil {
		return err
	}
	if _, err := sink.Write(blob); err != nil {
		return fmt.Errorf("x509: write certificate request: %w", err)
	}
	return nil
}

// isPEMBlob 判断输入是否形如 PEM（首个非空白行以 "-----BEGIN" 开头）。
//
// isPEMBlob reports whether the input looks like PEM (the first
// non-blank line starts with "-----BEGIN").
func isPEMBlob(b []byte) bool {
	const marker = "-----BEGIN"
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
			continue
		}
		if len(b)-i < len(marker) {
			return false
		}
		return string(b[i:i+len(marker)]) == marker
	}
	return false
}
