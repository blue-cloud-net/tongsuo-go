package meta

import "testing"

// TestParseFormat 验证格式名解析与归一化。
//
// TestParseFormat verifies the parsing and normalisation of format names.
func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"PEM", FormatPEM, false},
		{"pem", FormatPEM, false},
		{" DER ", FormatDER, false},
		{"der", FormatDER, false},
		{"pkcs12", "", true},
	}
	for _, tt := range tests {
		got, err := ParseFormat(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestFormatString 验证格式名的文本形式。
//
// TestFormatString verifies the textual form of a format name.
func TestFormatString(t *testing.T) {
	if FormatPEM.String() != "PEM" {
		t.Errorf("FormatPEM.String() = %q, want %q", FormatPEM.String(), "PEM")
	}
	if FormatDER.String() != "DER" {
		t.Errorf("FormatDER.String() = %q, want %q", FormatDER.String(), "DER")
	}
}
