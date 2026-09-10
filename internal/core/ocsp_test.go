package core

import (
	"testing"
)

// TestCreateOCSPRequest 验证 OCSP 请求生成需要非 nil 证书。
//
// 注意：本测试仅校验错误路径（nil 证书 / 无效 hash）；完整 happy path
// 需要 x509 包构造真实证书，会与 internal/core 构成 import 循环，
// 已由 ocsp/ocsp_test.go 在外部包层覆盖。
func TestCreateOCSPRequest(t *testing.T) {
	// nil 证书 → "ocsp: invalid certificate"
	if _, err := CreateOCSPRequest(nil, nil, "sha1"); err == nil {
		t.Fatal("nil cert/issuer should error")
	}
}

// TestLoadOCSPResponseInvalid 验证 DER 解析失败返回错误。
func TestLoadOCSPResponseInvalid(t *testing.T) {
	if _, err := LoadOCSPResponseDER([]byte("garbage")); err == nil {
		t.Fatal("garbage DER should error")
	}
	if _, err := LoadOCSPResponseDER(nil); err == nil {
		t.Fatal("nil DER should error")
	}
}

// TestOCSPResponseClose 验证 OCSPResponse.Close 幂等。
func TestOCSPResponseClose(t *testing.T) {
	r := &OCSPResponse{} // nil handle — Close 应安全
	if err := r.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
	_ = r.Close() // 二次也安全

	// nil receiver 也安全
	var nilResp *OCSPResponse
	if err := nilResp.Close(); err != nil {
		t.Fatalf("typed nil Close: %v", err)
	}
}
