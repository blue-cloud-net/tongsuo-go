package core

import "testing"

// TestVersionText 验证能获取铜锁版本字符串。
func TestVersionText(t *testing.T) {
	s := VersionText()
	if s == "" {
		t.Fatal("VersionText() returned empty string")
	}
	t.Logf("Tongsuo version: %s", s)
}

// TestVersionNum 验证 OpenSSL_version_num 非零。
func TestVersionNum(t *testing.T) {
	if VersionNum() == 0 {
		t.Fatal("VersionNum() returned 0")
	}
}

// TestTongsuoVersionNum 验证 Tongsuo_version_num 非零。
func TestTongsuoVersionNum(t *testing.T) {
	if TongsuoVersionNum() == 0 {
		t.Fatal("TongsuoVersionNum() returned 0")
	}
}
