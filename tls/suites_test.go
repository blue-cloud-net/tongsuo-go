package tls

import (
	"strings"
	"testing"
)

// TestCipherSuiteByName 验证按名称（大小写不敏感）与按 16 位 ID（十进制 /
// 0x 前缀十六进制）查找套件，以及空入参 / 未命中时返回错误。
//
// TestCipherSuiteByName verifies lookup by name (case-insensitively) and by
// 16-bit ID (decimal or 0x-prefixed hex), plus the error paths for an empty
// argument and a miss.
func TestCipherSuiteByName(t *testing.T) {
	const tls13Name = "TLS_AES_128_GCM_SHA256"
	const tls13ID = 0x1301

	want, err := CipherSuiteByName(tls13Name)
	if err != nil {
		t.Fatalf("CipherSuiteByName(%q): %v", tls13Name, err)
	}
	if want.Name != tls13Name {
		t.Errorf("Name = %q, want %q", want.Name, tls13Name)
	}
	if want.ID != tls13ID {
		t.Errorf("ID = 0x%04x, want 0x%04x", want.ID, tls13ID)
	}
	if want.MinVersion != TLS1_3Version {
		t.Errorf("MinVersion = 0x%04x, want 0x%04x (TLS1.3)", want.MinVersion, TLS1_3Version)
	}

	// 名称大小写不敏感。
	lower, err := CipherSuiteByName(strings.ToLower(tls13Name))
	if err != nil {
		t.Fatalf("CipherSuiteByName(lowercase): %v", err)
	}
	if lower != want {
		t.Errorf("lowercase lookup = %+v, want %+v", lower, want)
	}

	// 按 ID：0x 前缀十六进制与十进制两种写法等价（0x1301 == 4865）。
	for _, idText := range []string{"0x1301", "0X1301", "4865"} {
		got, err := CipherSuiteByName(idText)
		if err != nil {
			t.Fatalf("CipherSuiteByName(%q): %v", idText, err)
		}
		if got != want {
			t.Errorf("CipherSuiteByName(%q) = %+v, want %+v", idText, got, want)
		}
	}

	// 经典名（非 TLS1.3）也应命中。
	legacy, err := CipherSuiteByName("ECDHE-RSA-AES256-GCM-SHA384")
	if err != nil {
		t.Fatalf("CipherSuiteByName(legacy): %v", err)
	}
	if legacy.ID == 0 || legacy.MinVersion == 0 {
		t.Errorf("legacy 结果字段不完整：%+v", legacy)
	}

	// 错误路径。
	for _, bad := range []string{"", "   ", "NO_SUCH_CIPHER_SUITE_X", "0xFFFF"} {
		if _, err := CipherSuiteByName(bad); err == nil {
			t.Errorf("CipherSuiteByName(%q) 应报错", bad)
		}
	}
}

// TestCipherSuiteByNameRoundTrip 验证枚举出来的每个套件都能被按名称与按 ID
// 反查回来（名称与 ID 一致）。
//
// 只比对 Name / ID，不比对 MinVersion：探测本身不做版本过滤（见
// TestCipherSuitesEnumerated 的说明），因此反查命中的版本可能低于枚举时的入参，
// 而 MinVersion 一律由 min_tls 字符串派生，两者本就同源。
//
// TestCipherSuiteByNameRoundTrip verifies that every enumerated suite can be
// looked up again by name and by ID, yielding the same Name and ID.
//
// MinVersion is deliberately not compared: the probe does not version-filter
// (see TestCipherSuitesEnumerated), so a lookup may match under a lower version
// than the one enumerated under, while MinVersion always derives from the
// min_tls string — the same source either way.
func TestCipherSuiteByNameRoundTrip(t *testing.T) {
	for _, v := range cipherProbeVersions {
		suites := CipherSuites(v)
		if len(suites) == 0 {
			t.Fatalf("version=0x%04x: 枚举为空，无法做反查", v)
		}
		for _, s := range suites {
			byName, err := CipherSuiteByName(s.Name)
			if err != nil {
				t.Fatalf("version=0x%04x: CipherSuiteByName(%q): %v", v, s.Name, err)
			}
			if byName.Name != s.Name || byName.ID != s.ID {
				t.Errorf("version=0x%04x: 按名反查 %q 得到 %+v", v, s.Name, byName)
			}
			byID, err := CipherSuiteByName(suiteIDText(s.ID))
			if err != nil {
				t.Fatalf("version=0x%04x: CipherSuiteByName(%q): %v", v, suiteIDText(s.ID), err)
			}
			if byID.ID != s.ID {
				t.Errorf("version=0x%04x: 按 ID 0x%04x 反查得到 0x%04x", v, s.ID, byID.ID)
			}
		}
	}
}

// suiteIDText 把 16 位套件 ID 渲染成十六进制文本（供测试反查用）。
//
// suiteIDText renders a 16-bit cipher ID as hex text for the round-trip test.
func suiteIDText(id uint16) string {
	const hexDigits = "0123456789abcdef"
	return "0x" + string([]byte{
		hexDigits[(id>>12)&0xf], hexDigits[(id>>8)&0xf],
		hexDigits[(id>>4)&0xf], hexDigits[id&0xf],
	})
}

// TestCipherSuiteByNameNTLS 验证 NTLS 套件（若当前铜锁构建启用了 NTLS 套件）
// 同样可按名称与 ID 反查。
//
// TestCipherSuiteByNameNTLS verifies that NTLS suites (when the Tongsuo build
// exposes any) are also resolvable by name and by ID.
func TestCipherSuiteByNameNTLS(t *testing.T) {
	suites := CipherSuites(NTLSVersion)
	if len(suites) == 0 {
		t.Skip("当前铜锁构建未暴露 NTLS 套件")
	}
	for _, s := range suites {
		got, err := CipherSuiteByName(s.Name)
		if err != nil {
			t.Fatalf("CipherSuiteByName(%q): %v", s.Name, err)
		}
		if got.ID != s.ID {
			t.Errorf("按名反查 %q 得到 ID 0x%04x, want 0x%04x", s.Name, got.ID, s.ID)
		}
	}
}
