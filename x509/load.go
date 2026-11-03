package x509

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

// LoadFromURI 从本地路径、file URI 或 "-"（stdin）加载证书与 CRL。
// 支持 PEM 多对象和单个 DER；调用方负责逐个 Close。
//
// LoadFromURI loads certificates and CRLs from a local path, file URI or "-" (stdin).
// It accepts multiple PEM objects or one DER object; callers must Close each result.
func LoadFromURI(uri string) ([]*Certificate, []*CRL, error) {
	if uri == "-" {
		return LoadFromReader(os.Stdin)
	}
	if strings.Contains(uri, "://") {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, nil, err
		}
		if u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") || u.RawQuery != "" || u.Fragment != "" {
			return nil, nil, fmt.Errorf("x509: only local file URIs are supported")
		}
		uri = u.Path
	}
	f, err := os.Open(uri)
	if err != nil {
		return nil, nil, fmt.Errorf("x509: open: %w", err)
	}
	defer f.Close()
	return LoadFromReader(f)
}

// LoadFromReader 加载 PEM 多对象或单个 DER 的证书/CRL，不关闭 reader。
// 忽略 PEM 密钥块；其他未知块或错误返回错误并释放已解析资源。
// 成功时调用方负责对每项调用 Close。
//
// LoadFromReader loads certificates/CRLs from multiple PEM objects or one DER object without closing the reader.
// PEM key blocks are ignored; unknown blocks or errors release all parsed resources and return an error.
// On success callers must Close each result.
func LoadFromReader(r io.Reader) (certs []*Certificate, crls []*CRL, retErr error) {
	if r == nil {
		return nil, nil, fmt.Errorf("x509: nil reader")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("x509: read: %w", err)
	}
	defer func() {
		if retErr != nil {
			for _, c := range certs {
				c.Close()
			}
			for _, c := range crls {
				c.Close()
			}
			certs = nil
			crls = nil
		}
	}()
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		c, err := LoadCertificateDER(data)
		if err == nil {
			return []*Certificate{c}, nil, nil
		}
		crl, err := LoadCRLDER(data)
		if err != nil {
			return nil, nil, err
		}
		return nil, []*CRL{crl}, nil
	}
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		b, tail := pem.Decode(rest)
		if b == nil {
			return certs, crls, fmt.Errorf("x509: malformed PEM")
		}
		rest = tail
		switch b.Type {
		case "CERTIFICATE", "TRUSTED CERTIFICATE":
			c, e := LoadTrustedCertificatePEM(pem.EncodeToMemory(b))
			if e != nil {
				return certs, crls, e
			}
			certs = append(certs, c)
		case "X509 CRL":
			c, e := LoadCRLDER(b.Bytes)
			if e != nil {
				return certs, crls, e
			}
			crls = append(crls, c)
		case "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PUBLIC KEY", "RSA PUBLIC KEY":
			continue
		default:
			return certs, crls, fmt.Errorf("x509: unsupported PEM type %q", b.Type)
		}
	}
	if len(certs)+len(crls) == 0 {
		return nil, nil, fmt.Errorf("x509: no certificates or CRLs found")
	}
	return certs, crls, nil
}
