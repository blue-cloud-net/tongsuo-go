// Package pkcs7 基于铜锁原生实现实现 PKCS#7 容器（P7B 证书集合交换）。
// 提供证书集合的打包（Build）与提取（Extract），支持 DER 与 PEM（"BEGIN PKCS7"）。
//
// Package pkcs7 implements the PKCS#7 container (P7B certificate-bag) backed
// by the Tongsuo native library. It provides Build and Extract for certificate
// bundles; both DER and PEM ("BEGIN PKCS7") formats are supported.
package pkcs7

import (
	"bytes"
	"encoding/pem"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	tx509 "github.com/blue-cloud-net/tongsuo-go/x509"
)

// Build 构建包含证书集合的 PKCS#7（SignedData，无签名者，仅证书），返回 DER。
// certs 中的 nil 条目会被静默跳过。
//
// Build wraps a certificate bundle into a PKCS#7 SignedData structure
// (signer info empty, certificates only) and returns the DER encoding. nil
// entries in certs are silently skipped.
func Build(certs []*tx509.Certificate) ([]byte, error) {
	p7, err := core.NewPKCS7SignedData()
	if err != nil {
		return nil, err
	}
	defer p7.Close()
	for _, c := range certs {
		if c == nil {
			continue
		}
		if err := p7.AddCertificate(c.Core()); err != nil {
			return nil, err
		}
	}
	return p7.MarshalDER()
}

// MarshalPEM 将 PKCS#7 DER 编码为 PEM（"BEGIN PKCS7"）。
//
// MarshalPEM re-encodes a PKCS#7 DER blob as PEM using the "PKCS7" type
// label (i.e. "-----BEGIN PKCS7-----").
func MarshalPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
}

// Extract 从 PKCS#7（DER 或 PEM）提取证书。
// 输入支持 DER 或 PEM（含 "BEGIN PKCS7" 头）；返回按叶到根顺序排列的
// *x509.Certificate 包装列表。
//
// Extract reads certificates out of a PKCS#7 container given as DER or PEM
// (with "BEGIN PKCS7" header); it returns the leaf-first list of
// *x509.Certificate wrappers.
func Extract(data []byte) ([]*tx509.Certificate, error) {
	der, err := decode(data)
	if err != nil {
		return nil, err
	}
	p7, err := core.LoadPKCS7DER(der)
	if err != nil {
		return nil, err
	}
	defer p7.Close()
	certs, err := p7.Certificates()
	if err != nil {
		return nil, err
	}
	out := make([]*tx509.Certificate, 0, len(certs))
	for _, c := range certs {
		out = append(out, tx509.WrapCertificate(c))
	}
	return out, nil
}

// decode 自动识别 PEM / DER 并返回 DER。
//
// decode inspects the input and returns the DER bytes, transparently
// stripping a PEM "PKCS7" envelope when present.
func decode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: empty data")
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("pkcs7: invalid PEM")
		}
		return block.Bytes, nil
	}
	return data, nil
}
