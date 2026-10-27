package x509

import (
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestNameHelpers 验证 Name.Nid / Name.Len / SubjectText / IssuerEntries / SubjectEntries。
func TestNameHelpers(t *testing.T) {
	n := NewName().Add("CN", "name.example.com").Add("O", "Name Org").Add("C", "CN")
	if n.Len() != 3 {
		t.Fatalf("Name.Len = %d, want 3", n.Len())
	}
	if n.Nid("CN") == 0 {
		t.Fatal("Name.Nid(\"CN\") = 0, want nonzero")
	}
	if n.Nid("") != 0 {
		t.Fatalf("Name.Nid(\"\") = %d, want 0", n.Nid(""))
	}
	if n.Nid("unknown-field-xyz") != 0 {
		t.Fatal("Name.Nid(unknown) should return 0")
	}
	if n.String() == "" {
		t.Fatal("Name.String() should not be empty")
	}

	// CSR SubjectEntries / SubjectText
	priv, _ := asym.GenerateSM2()
	req, _ := NewCertificateRequest(n, priv.Public(), priv)
	entries := req.SubjectEntries()
	if len(entries) != 3 {
		t.Fatalf("CSR SubjectEntries = %d, want 3", len(entries))
	}
	if req.SubjectText() == "" {
		t.Fatal("CSR SubjectText should not be empty")
	}
}

// TestNameNonASCII 验证非 ASCII RDN 值写入后读回逐字符保真。
//
// 覆盖：CJK 单值、ASCII/CJK 混合、非 BMP 字符（emoji）、超长值（> 255 字节）、
// 上限边界值、空值。此前的 MBSTRING_ASC 会把每个 UTF-8 字节当作 Latin-1 字符再
// 编码一次（「海峰」由 6 字节变 12 字节），读回即 mojibake。
func TestNameNonASCII(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"cn-cjk", "CN", "海峰"},
		{"o-cjk", "O", "示例公司"},
		{"ou-cjk", "OU", "研发部"},
		{"l-cjk", "L", "杭州市"},
		{"st-cjk", "ST", "浙江省"},
		{"mixed", "O", "示例公司-Example Corp"},
		{"cjk-with-space", "CN", "海峰 (Hai Feng)"},
		{"non-bmp", "CN", "🔐海峰"},
		{"long-l", "L", strings.Repeat("杭", 100)}, // 300 字节，压过旧的 256 字节缓冲
		{"edge-o", "O", strings.Repeat("锁", 64)},  // organizationName 上限 64 字符
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			n := NewName()
			if err := n.TryAdd(c.field, c.value); err != nil {
				t.Fatalf("TryAdd(%q, %q): %v", c.field, c.value, err)
			}
			entries := n.Entries()
			if len(entries) != 1 {
				t.Fatalf("Entries = %d, want 1", len(entries))
			}
			if entries[0].Field != c.field {
				t.Fatalf("Field = %q, want %q", entries[0].Field, c.field)
			}
			if entries[0].Value != c.value {
				t.Fatalf("Entries value = %q (% x), want %q (% x)",
					entries[0].Value, entries[0].Value, c.value, c.value)
			}
			if got := n.Get(c.field); got != c.value {
				t.Fatalf("Get(%q) = %q (% x), want %q (% x)",
					c.field, got, got, c.value, c.value)
			}
			if n.Len() != 1 {
				t.Fatalf("Len = %d, want 1", n.Len())
			}
		})
	}
}

// TestNameNonASCIIMultiRDN 验证多条 CJK / ASCII 混合 RDN 的值均保真。
//
// 本用例不校验 RDN 顺序：底层 `X509_NAME_add_entry_by_txt` 以 loc=0 插入，条目
// 顺序与调用顺序相反（见 TestCertificateNonASCIISubjectRoundTrip 的顺序保真断言）。
func TestNameNonASCIIMultiRDN(t *testing.T) {
	adds := []struct {
		field string
		value string
	}{
		{"C", "CN"},
		{"ST", "浙江省"},
		{"L", "杭州市"},
		{"O", "示例公司"},
		{"CN", "海峰"},
	}
	n := NewName()
	for _, a := range adds {
		if err := n.TryAdd(a.field, a.value); err != nil {
			t.Fatalf("TryAdd(%q, %q): %v", a.field, a.value, err)
		}
	}
	entries := n.Entries()
	if len(entries) != len(adds) {
		t.Fatalf("Entries = %d, want %d", len(entries), len(adds))
	}
	seen := make(map[string]string, len(entries))
	for _, e := range entries {
		if _, dup := seen[e.Field]; dup {
			t.Fatalf("duplicate entry for %q", e.Field)
		}
		seen[e.Field] = e.Value
	}
	for _, a := range adds {
		if got := seen[a.field]; got != a.value {
			t.Fatalf("entry %s = %q (% x), want %q", a.field, got, got, a.value)
		}
		if got := n.Get(a.field); got != a.value {
			t.Fatalf("Get(%q) = %q, want %q", a.field, got, a.value)
		}
	}
}

// TestNameInvalidUTF8 验证非法 UTF-8 值被拒绝，且不留半成品条目。
func TestNameInvalidUTF8(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"invalid-bytes", "\xff\xfe"},
		{"surrogate", "\xed\xa0\x80"},
		{"truncated-tail", "海\xe6\xb5"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			n := NewName()
			err := n.TryAdd("CN", c.value)
			if err == nil {
				t.Fatalf("TryAdd(% x) = nil error, want error for invalid UTF-8", c.value)
			}
			if !strings.Contains(err.Error(), "UTF-8") {
				t.Fatalf("error = %v, want it to mention UTF-8", err)
			}
			if got := n.Len(); got != 0 {
				t.Fatalf("Len = %d after rejected value, want 0", got)
			}
		})
	}
}

// TestNameAddPanicsOnInvalidUTF8 验证 Add 对非法 UTF-8 走 panic 分支（编程错误语义）。
func TestNameAddPanicsOnInvalidUTF8(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Add with invalid UTF-8 should panic")
		}
	}()
	NewName().Add("CN", "\xff")
}

// TestNameRejectNonASCIIForRestrictedTypes 验证字符集 / 长度受限字段拒绝非 ASCII 值及空值。
//
// 实测（铜锁 8.5.0-pre1，MBSTRING_UTF8）：countryName（PrintableString、长度 2）与
// emailAddress（IA5String）都返回 ASN1_mbstring_ncopy "illegal characters"；
// 空值则因字段 minsize=1 返回 "string too short"。
func TestNameRejectNonASCIIForRestrictedTypes(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"countryName", "C", "中国"},
		{"emailAddress", "emailAddress", "海峰@example.com"},
		{"empty-value", "OU", ""}, // minsize=1，与 MBSTRING 类型无关
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			n := NewName()
			if err := n.TryAdd(c.field, c.value); err == nil {
				t.Fatalf("TryAdd(%q, %q) = nil error, want charset error", c.field, c.value)
			}
			if got := n.Len(); got != 0 {
				t.Fatalf("Len = %d after rejected value, want 0", got)
			}
			// 同一字段的 ASCII 值仍应成功，确认拒绝源于字符集而非字段名
			ascii := "CN"
			if c.field == "emailAddress" {
				ascii = "ops@example.com"
			}
			if err := n.TryAdd(c.field, ascii); err != nil {
				t.Fatalf("TryAdd(%q, %q): %v", c.field, ascii, err)
			}
		})
	}
}

// TestNameAddOrder 验证 Add 按调用顺序追加（DER 顺序 = 书写顺序，与 openssl -subj 一致）。
func TestNameAddOrder(t *testing.T) {
	n := NewName().Add("C", "CN").Add("O", "Example Corp").
		Add("OU", "R&D").Add("CN", "example.com")
	want := []struct{ field, value string }{
		{"C", "CN"},
		{"O", "Example Corp"},
		{"OU", "R&D"},
		{"CN", "example.com"},
	}
	got := n.Entries()
	if len(got) != len(want) {
		t.Fatalf("Entries = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Field != want[i].field || got[i].Value != want[i].value {
			t.Fatalf("entry[%d] = {%s=%q}, want {%s=%q}",
				i, got[i].Field, got[i].Value, want[i].field, want[i].value)
		}
	}
	// String() 走 X509_NAME_oneline，按 DER 前向打印，因此与书写顺序一致
	if s := n.String(); s != "/C=CN/O=Example Corp/OU=R&D/CN=example.com" {
		t.Fatalf("String() = %q, want /C=CN/O=Example Corp/OU=R&D/CN=example.com", s)
	}
}
