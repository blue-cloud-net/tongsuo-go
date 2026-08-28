// Package pkcs7 基于铜锁原生实现实现 PKCS#7 容器（P7B 证书集合交换）。
//
// 提供证书集合的打包（Build）与提取（Extract），支持 DER 与 PEM（"BEGIN PKCS7"）。
package pkcs7

import (
	"bytes"
	"encoding/pem"
	"fmt"

	tx509 "github.com/blue-cloud-net/tongsuo-go/crypto/x509"
	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Build 构建包含证书集合的 PKCS#7（SignedData，无签名者，仅证书），返回 DER。
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
func MarshalPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
}

// Extract 从 PKCS#7（DER 或 PEM）提取证书。
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
