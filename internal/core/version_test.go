package core

import (
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/internal/native"
	"os"
	"testing"
)

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

// TestNativeVersionIdentity 验证编译头文件、运行库及 CI 指定版本同源。
//
// TestNativeVersionIdentity verifies build headers, loaded library and the CI release identity.
func TestNativeVersionIdentity(t *testing.T) {
	header, loaded := native.TongsuoHeaderVersionNum(), native.TongsuoVersionNum()&0xffffffff
	if header != loaded {
		t.Fatalf("Tongsuo header/library mismatch: %#x vs %#x", header, loaded)
	}
	if expected := os.Getenv("TONGSUO_EXPECT_VERSION"); expected != "" {
		got := fmt.Sprintf("%d.%d.%d", loaded>>28, (loaded>>20)&255, (loaded>>4)&65535)
		if got != expected {
			t.Fatalf("Tongsuo library=%s, expected %s", got, expected)
		}
	}
}
