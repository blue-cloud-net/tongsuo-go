package x509

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// certPolGoldenBare 是「单策略、无限定符」的黄金向量。
//
// 该向量与铜锁 openssl 用 `policyIdentifier = 1.2.3.4` 生成的证书扩展
// 逐字节一致（无限定符时 policyQualifiers 整个省略）。
//
// certPolGoldenBare is the golden vector for a single policy without
// qualifiers.
//
// It matches byte for byte the extension the Tongsuo openssl command line
// produces for `policyIdentifier = 1.2.3.4` (the policyQualifiers field is
// omitted entirely when there is no qualifier).
const certPolGoldenBare = "3007300506032A0304"

// certPolGoldenOpenSSL 是铜锁 openssl 实际产出的「单策略 + 2 个 CPS +
// userNotice」扩展值（159 字节）。
//
// certPolGoldenOpenSSL is the certificatePolicies extension value (159
// bytes) that the Tongsuo openssl command line actually produces for a single
// policy carrying two CPS qualifiers and a userNotice.
const certPolGoldenOpenSSL = "30819C30819906032A0304308191302606082B060105050" +
	"70201161A687474703A2F2F6370732E6578616D706C652E636F6D2F637073302806082B060" +
	"10505070201161C68747470733A2F2F6370732E6578616D706C652E636F6D2F63707332303D06" +
	"082B06010505070202303130181A0B4578616D706C65204F726730090201010201020201031A15" +
	"5468697320697320612075736572206E6F74696365"

// certPolGoldenFull 与 certPolGoldenOpenSSL 结构相同，唯一差别是
// organization 与 explicitText 用 UTF8String（0x0C）而非 openssl 的
// VisibleString（0x1A）——openssl 对非 ASCII 内容用 VisibleString 会产出
// 不合规的 DER，本库改用合规且同样可被 openssl 读回的 UTF8String。
//
// certPolGoldenFull has the same structure as certPolGoldenOpenSSL; the only
// difference is that organization and explicitText use UTF8String (0x0C)
// instead of openssl's VisibleString (0x1A) — openssl produces non-conformant
// DER for non-ASCII content in VisibleString, while this library uses the
// conformant UTF8String that openssl reads back just as well.
const certPolGoldenFull = "30819C30819906032A0304308191302606082B060105050" +
	"70201161A687474703A2F2F6370732E6578616D706C652E636F6D2F637073302806082B060" +
	"10505070201161C68747470733A2F2F6370732E6578616D706C652E636F6D2F63707332303D06" +
	"082B06010505070202303130180C0B4578616D706C65204F726730090201010201020201030C15" +
	"5468697320697320612075736572206E6F74696365"

// certPolFullPolicy 是 certPolGoldenFull 对应的唯一一条策略。
//
// certPolFullPolicy is the single policy corresponding to certPolGoldenFull.
func certPolFullPolicy() CertificatePolicy {
	return CertificatePolicy{
		OID: "1.2.3.4",
		CPSURIs: []string{
			"http://cps.example.com/cps",
			"https://cps.example.com/cps2",
		},
		UserNotice: &UserNotice{
			Organization:  "Example Org",
			NoticeNumbers: []int{1, 2, 3},
			ExplicitText:  "This is a user notice",
		},
	}
}

// TestEncodeCertificatePoliciesGolden 验证编码结果与黄金向量逐字节一致。
//
// TestEncodeCertificatePoliciesGolden verifies that the encoding matches the
// golden vectors byte for byte.
func TestEncodeCertificatePoliciesGolden(t *testing.T) {
	tests := []struct {
		name     string
		policies []CertificatePolicy
		wantHex  string
	}{
		{
			name:     "single policy without qualifier",
			policies: []CertificatePolicy{{OID: "1.2.3.4"}},
			wantHex:  certPolGoldenBare,
		},
		{
			name:     "single policy with cps and user notice",
			policies: []CertificatePolicy{certPolFullPolicy()},
			wantHex:  certPolGoldenFull,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeCertificatePolicies(tt.policies)
			if err != nil {
				t.Fatalf("encodeCertificatePolicies: %v", err)
			}
			want, err := hex.DecodeString(tt.wantHex)
			if err != nil {
				t.Fatalf("bad golden vector: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoding mismatch\n got: %X\nwant: %X", got, want)
			}
		})
	}
}

// TestParseCertificatePoliciesGolden 验证黄金向量能原样解析回来。
//
// TestParseCertificatePoliciesGolden verifies that the golden vectors parse
// back unchanged.
func TestParseCertificatePoliciesGolden(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
		want   []CertificatePolicy
	}{
		{
			name:   "bare",
			hexStr: certPolGoldenBare,
			want:   []CertificatePolicy{{OID: "1.2.3.4"}},
		},
		{
			name:   "full",
			hexStr: certPolGoldenFull,
			want:   []CertificatePolicy{certPolFullPolicy()},
		},
		{
			// openssl 用 VisibleString，本库必须能读回。
			name:   "openssl visible string variant",
			hexStr: certPolGoldenOpenSSL,
			want:   []CertificatePolicy{certPolFullPolicy()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("bad golden vector: %v", err)
			}
			got, err := parseCertificatePolicies(der)
			if err != nil {
				t.Fatalf("parseCertificatePolicies: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

// TestCertificatePoliciesRoundTrip 验证编码后再解析结果一致。
//
// TestCertificatePoliciesRoundTrip verifies that parsing an encoded policy
// list yields the same value.
func TestCertificatePoliciesRoundTrip(t *testing.T) {
	policies := []CertificatePolicy{
		{OID: "1.2.3.4"},
		{OID: "1.2.3.5", CPSURIs: []string{"http://a.example.com"}},
		{
			OID:     "2.5.29.32.0",
			CPSURIs: []string{"https://b.example.com/cps"},
			UserNotice: &UserNotice{
				Organization:  "示例机构",
				NoticeNumbers: []int{7},
				ExplicitText:  "本机构发布的证书策略说明",
			},
		},
		{
			OID:        "1.3.6.1.4.1.99999.1",
			UserNotice: &UserNotice{ExplicitText: "只有文本"},
		},
		{
			OID:     "1.3.6.1.4.1.99999.2",
			CPSURIs: []string{"http://c.example.com", "http://d.example.com"},
		},
	}
	der, err := encodeCertificatePolicies(policies)
	if err != nil {
		t.Fatalf("encodeCertificatePolicies: %v", err)
	}
	got, err := parseCertificatePolicies(der)
	if err != nil {
		t.Fatalf("parseCertificatePolicies: %v", err)
	}
	if !reflect.DeepEqual(got, policies) {
		t.Fatalf("round trip mismatch\n got: %+v\nwant: %+v", got, policies)
	}
}

// TestEncodeCertificatePoliciesErrors 验证写侧的输入校验。
//
// TestEncodeCertificatePoliciesErrors verifies the write-side input
// validation.
func TestEncodeCertificatePoliciesErrors(t *testing.T) {
	tests := []struct {
		name     string
		policies []CertificatePolicy
		wantErr  string
	}{
		{
			name:     "empty list",
			policies: nil,
			wantErr:  "no policy given",
		},
		{
			name:     "empty oid",
			policies: []CertificatePolicy{{OID: ""}},
			wantErr:  "empty OID",
		},
		{
			name:     "single arc oid",
			policies: []CertificatePolicy{{OID: "1"}},
			wantErr:  "need at least two arcs",
		},
		{
			name:     "non numeric oid",
			policies: []CertificatePolicy{{OID: "1.2.x"}},
			wantErr:  "bad arc",
		},
		{
			name:     "first arc too large",
			policies: []CertificatePolicy{{OID: "3.2.1"}},
			wantErr:  "first arc must be 0, 1 or 2",
		},
		{
			name:     "second arc too large",
			policies: []CertificatePolicy{{OID: "1.40.1"}},
			wantErr:  "second arc must not exceed 39",
		},
		{
			name:     "duplicate oid",
			policies: []CertificatePolicy{{OID: "1.2.3"}, {OID: "1.2.3"}},
			wantErr:  "duplicate policy OID",
		},
		{
			name:     "empty cps uri",
			policies: []CertificatePolicy{{OID: "1.2.3", CPSURIs: []string{""}}},
			wantErr:  "empty CPS URI",
		},
		{
			name:     "non ascii cps uri",
			policies: []CertificatePolicy{{OID: "1.2.3", CPSURIs: []string{"http://例.example.com"}}},
			wantErr:  "non-IA5 characters",
		},
		{
			name: "notice numbers without organization",
			policies: []CertificatePolicy{{OID: "1.2.3", UserNotice: &UserNotice{
				NoticeNumbers: []int{1},
			}}},
			wantErr: "notice numbers require an organization",
		},
		{
			name:     "empty user notice",
			policies: []CertificatePolicy{{OID: "1.2.3", UserNotice: &UserNotice{}}},
			wantErr:  "empty user notice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encodeCertificatePolicies(tt.policies)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestParseCertificatePoliciesErrors 验证畸形 DER 被拒绝。
//
// TestParseCertificatePoliciesErrors verifies that malformed DER is
// rejected.
func TestParseCertificatePoliciesErrors(t *testing.T) {
	full, err := hex.DecodeString(certPolGoldenFull)
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	tests := []struct {
		name    string
		der     []byte
		wantErr string
	}{
		{name: "empty", der: nil, wantErr: "truncated element"},
		{name: "not a sequence", der: []byte{0x04, 0x01, 0x00}, wantErr: "expected a SEQUENCE"},
		{name: "truncated", der: full[:len(full)-5], wantErr: "truncated"},
		{
			name:    "trailing bytes",
			der:     append(append([]byte{}, full...), 0x00),
			wantErr: "trailing bytes",
		},
		{
			name:    "empty policy sequence",
			der:     []byte{0x30, 0x00},
			wantErr: "policy sequence is empty",
		},
		{
			name:    "policy information not a sequence",
			der:     []byte{0x30, 0x03, 0x02, 0x01, 0x01},
			wantErr: "policy information must be a SEQUENCE",
		},
		{
			name:    "policy identifier not an oid",
			der:     []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01},
			wantErr: "policy identifier must be an OBJECT IDENTIFIER",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCertificatePolicies(tt.der)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestParseCertificatePoliciesSkipsUnknownQualifier 验证未知限定符 OID 被跳过
// 而不是报错——RFC 5280 允许扩展限定符类型。
//
// TestParseCertificatePoliciesSkipsUnknownQualifier verifies that an unknown
// qualifier OID is skipped instead of rejected — RFC 5280 allows extending
// the set of qualifiers.
func TestParseCertificatePoliciesSkipsUnknownQualifier(t *testing.T) {
	// SEQUENCE { SEQUENCE { OID 1.2.3.4, SEQUENCE { SEQUENCE { OID 1.2.3.5.6, IA5String "x" } } } }
	der, err := hex.DecodeString("3014301206032A0304300B300906042A030506160178")
	if err != nil {
		t.Fatalf("bad vector: %v", err)
	}
	policies, err := parseCertificatePolicies(der)
	if err != nil {
		t.Fatalf("parseCertificatePolicies: %v", err)
	}
	want := []CertificatePolicy{{OID: "1.2.3.4"}}
	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("policy mismatch\n got: %+v\nwant: %+v", policies, want)
	}
}

// TestEncodeOIDRoundTrip 验证 OID 编解码在各种形态下可逆。
//
// TestEncodeOIDRoundTrip verifies that OID encoding and decoding round trip
// for a variety of shapes.
func TestEncodeOIDRoundTrip(t *testing.T) {
	oids := []string{
		"1.2.3.4",
		"0.0",
		"0.39",
		"1.39",
		"2.5.29.32",
		"2.5.29.32.0",
		"1.3.6.1.4.1.311.21.20",
		"1.2.840.113549.1.1.11",
		"1.2.156.10197.1.501",
		"2.999.1",
	}
	for _, oid := range oids {
		t.Run(oid, func(t *testing.T) {
			encoded, err := encodeOID(oid)
			if err != nil {
				t.Fatalf("encodeOID(%q): %v", oid, err)
			}
			got := decodeOID(encoded)
			if got != oid {
				t.Fatalf("round trip mismatch: got %q want %q", got, oid)
			}
		})
	}
}

// TestEncodeOIDMatchesOpenSSL 验证前两弧的合并规则与 OpenSSL 一致。
//
// TestEncodeOIDMatchesOpenSSL verifies that the merging of the first two
// arcs matches OpenSSL.
func TestEncodeOIDMatchesOpenSSL(t *testing.T) {
	tests := []struct {
		oid     string
		wantHex string
	}{
		{oid: "1.2.3.4", wantHex: "2A0304"},
		{oid: "2.5.29.32", wantHex: "551D20"},
		{oid: "1.3.6.1.5.5.7.2.1", wantHex: "2B06010505070201"},
	}
	for _, tt := range tests {
		t.Run(tt.oid, func(t *testing.T) {
			got, err := encodeOID(tt.oid)
			if err != nil {
				t.Fatalf("encodeOID(%q): %v", tt.oid, err)
			}
			want, err := hex.DecodeString(tt.wantHex)
			if err != nil {
				t.Fatalf("bad vector: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoding mismatch\n got: %X\nwant: %X", got, want)
			}
		})
	}
}

// TestEncodeDecodeInteger 验证整数的补码编解码。
//
// TestEncodeDecodeInteger verifies the two's complement encoding and decoding
// of integers.
func TestEncodeDecodeInteger(t *testing.T) {
	tests := []struct {
		value   int
		wantHex string
	}{
		{value: 0, wantHex: "00"},
		{value: 1, wantHex: "01"},
		{value: 127, wantHex: "7F"},
		{value: 128, wantHex: "0080"},
		{value: 255, wantHex: "00FF"},
		{value: 256, wantHex: "0100"},
		{value: -1, wantHex: "FF"},
		{value: -128, wantHex: "80"},
		{value: -129, wantHex: "FF7F"},
	}
	for _, tt := range tests {
		t.Run(tt.wantHex, func(t *testing.T) {
			got := encodeInteger(tt.value)
			want, err := hex.DecodeString(tt.wantHex)
			if err != nil {
				t.Fatalf("bad vector: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoding mismatch\n got: %X\nwant: %X", got, want)
			}
			back, err := decodeInteger(got)
			if err != nil {
				t.Fatalf("decodeInteger: %v", err)
			}
			if back != tt.value {
				t.Fatalf("round trip mismatch: got %d want %d", back, tt.value)
			}
		})
	}
}

// TestDerTLVLongFormLength 验证超过 127 字节时长度改用长式编码。
//
// TestDerTLVLongFormLength verifies that lengths beyond 127 bytes switch to
// the long form.
func TestDerTLVLongFormLength(t *testing.T) {
	if got := derLen(127); !bytes.Equal(got, []byte{0x7f}) {
		t.Fatalf("derLen(127) = %X, want 7F", got)
	}
	if got := derLen(128); !bytes.Equal(got, []byte{0x81, 0x80}) {
		t.Fatalf("derLen(128) = %X, want 8180", got)
	}
	if got := derLen(300); !bytes.Equal(got, []byte{0x82, 0x01, 0x2c}) {
		t.Fatalf("derLen(300) = %X, want 82012C", got)
	}
}
