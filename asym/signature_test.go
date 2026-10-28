package asym

import (
	"bytes"
	"testing"
)

// TestSignaturePartsAndDERRoundTrip 验证 DER → (r, s) → DER 的往返一致性。
// 用真实签名覆盖 SM2 与 ECDSA 两条产生 DER 签名的路径。
//
// TestSignaturePartsAndDERRoundTrip verifies the DER → (r, s) → DER
// round trip using real signatures from both SM2 and ECDSA.
func TestSignaturePartsAndDERRoundTrip(t *testing.T) {
	msg := []byte("signature format round trip")

	cases := []struct {
		name string
		der  []byte
	}{
		{name: "SM2", der: mustSM2Signature(t, msg)},
		{name: "ECDSA-P256", der: mustECDSASignature(t, msg)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, s, err := SignatureParts(c.der)
			if err != nil {
				t.Fatalf("SignatureParts: %v", err)
			}
			if len(r) == 0 || len(s) == 0 {
				t.Fatalf("empty component: r=%d s=%d", len(r), len(s))
			}
			back, err := SignatureDER(r, s)
			if err != nil {
				t.Fatalf("SignatureDER: %v", err)
			}
			if !bytes.Equal(back, c.der) {
				t.Errorf("DER round trip mismatch:\n  got  %x\n  want %x", back, c.der)
			}
		})
	}
}

// TestFormatSignatureSM2 验证 SM2 签名的 der → raw → der 往返（宽度 32）。
//
// TestFormatSignatureSM2 verifies the der → raw → der round trip for SM2
// signatures (width 32).
func TestFormatSignatureSM2(t *testing.T) {
	der := mustSM2Signature(t, []byte("sm2 raw format"))

	raw, err := FormatSignature(der, "der", "raw", 32)
	if err != nil {
		t.Fatalf("der->raw: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("raw length = %d, want 64", len(raw))
	}
	back, err := FormatSignature(raw, "raw", "der", 32)
	if err != nil {
		t.Fatalf("raw->der: %v", err)
	}
	if !bytes.Equal(back, der) {
		t.Errorf("round trip mismatch:\n  got  %x\n  want %x", back, der)
	}

	// 从 raw 转 der 时可省略宽度（按长度推断）
	back2, err := FormatSignature(raw, "raw", "der", 0)
	if err != nil {
		t.Fatalf("raw->der with inferred width: %v", err)
	}
	if !bytes.Equal(back2, der) {
		t.Errorf("inferred width mismatch:\n  got  %x\n  want %x", back2, der)
	}
}

// TestFormatSignatureECDSA 验证 ECDSA（P-256）签名的定长转换。
//
// TestFormatSignatureECDSA verifies fixed-width conversion for ECDSA
// (P-256) signatures.
func TestFormatSignatureECDSA(t *testing.T) {
	der := mustECDSASignature(t, []byte("ecdsa raw format"))

	raw, err := FormatSignature(der, "der", "raw", 32)
	if err != nil {
		t.Fatalf("der->raw: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("raw length = %d, want 64", len(raw))
	}
	back, err := FormatSignature(raw, "raw", "der", 32)
	if err != nil {
		t.Fatalf("raw->der: %v", err)
	}
	if !bytes.Equal(back, der) {
		t.Errorf("round trip mismatch:\n  got  %x\n  want %x", back, der)
	}
}

// TestFormatSignatureLeadingZeroPadding 验证分段高位为 0 时的定长左补零。
// 构造 r 与 s 都带前导 0x00 的场景：DER 会更短，raw 必须补回 32 字节。
//
// TestFormatSignatureLeadingZeroPadding verifies fixed-width left padding
// when a component's high bit is clear: DER gets shorter while raw must
// be padded back to 32 bytes.
func TestFormatSignatureLeadingZeroPadding(t *testing.T) {
	// r、s 最高位为 0（0x7f...），DER 编码会省略前导 0x00
	r := append([]byte{0x7f}, bytes.Repeat([]byte{0x11}, 31)...)
	s := append([]byte{0x3c}, bytes.Repeat([]byte{0x22}, 31)...)
	der, err := SignatureDER(r, s)
	if err != nil {
		t.Fatalf("SignatureDER: %v", err)
	}

	raw, err := FormatSignature(der, "der", "raw", 32)
	if err != nil {
		t.Fatalf("der->raw: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("raw length = %d, want 64", len(raw))
	}
	if !bytes.Equal(raw[:32], r) {
		t.Errorf("r component not padded correctly:\n  got  %x\n  want %x", raw[:32], r)
	}
	if !bytes.Equal(raw[32:], s) {
		t.Errorf("s component not padded correctly:\n  got  %x\n  want %x", raw[32:], s)
	}

	back, err := FormatSignature(raw, "raw", "der", 32)
	if err != nil {
		t.Fatalf("raw->der: %v", err)
	}
	if !bytes.Equal(back, der) {
		t.Errorf("round trip mismatch:\n  got  %x\n  want %x", back, der)
	}
}

// TestFormatSignatureErrors 验证参数与结构错误路径。
//
// TestFormatSignatureErrors verifies the argument and structure error
// paths.
func TestFormatSignatureErrors(t *testing.T) {
	der := mustSM2Signature(t, []byte("errors"))

	if _, err := FormatSignature(der, "der", "raw", 0); err == nil {
		t.Error("der->raw without width: want error")
	}
	if _, err := FormatSignature(der, "der", "raw", 8); err == nil {
		t.Error("der->raw with too-small width: want error")
	}
	if _, err := FormatSignature(der, "asn1", "raw", 32); err == nil {
		t.Error("unknown from format: want error")
	}
	if _, err := FormatSignature(der, "der", "pkcs1", 32); err == nil {
		t.Error("unknown to format: want error")
	}
	if _, err := FormatSignature([]byte{1, 2, 3}, "raw", "der", 0); err == nil {
		t.Error("odd raw length: want error")
	}
	if _, err := FormatSignature([]byte{1, 2, 3, 4}, "raw", "der", 3); err == nil {
		t.Error("raw length/width mismatch: want error")
	}
	if _, _, err := SignatureParts([]byte{0x30, 0x00}); err == nil {
		t.Error("empty sequence: want error")
	}
	if _, _, err := SignatureParts([]byte("not a der signature")); err == nil {
		t.Error("garbage input: want error")
	}
	// 尾随字节必须被拒绝
	withTail := append(append([]byte{}, der...), 0x00)
	if _, _, err := SignatureParts(withTail); err == nil {
		t.Error("trailing byte: want error")
	}
	if _, err := SignatureDER(nil, []byte{1}); err == nil {
		t.Error("empty r: want error")
	}
	if _, err := SignatureDER([]byte{0}, []byte{1}); err == nil {
		t.Error("zero r: want error")
	}
}

// TestFormatSignatureIdentity 验证 from == to 时返回入参副本。
//
// TestFormatSignatureIdentity verifies from == to returns a copy of the
// input.
func TestFormatSignatureIdentity(t *testing.T) {
	der := mustSM2Signature(t, []byte("identity"))
	got, err := FormatSignature(der, "der", "der", 0)
	if err != nil {
		t.Fatalf("FormatSignature: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Errorf("identity mismatch:\n  got  %x\n  want %x", got, der)
	}
	got[0] ^= 0xff
	if bytes.Equal(got, der) {
		t.Error("result must be a copy, not an alias")
	}
}

// mustSM2Signature 生成一个 SM2 签名（DER）。
//
// mustSM2Signature produces one SM2 signature in DER form.
func mustSM2Signature(t *testing.T, msg []byte) []byte {
	t.Helper()
	priv, err := GenerateSM2()
	if err != nil {
		t.Fatalf("GenerateSM2: %v", err)
	}
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("SM2 Sign: %v", err)
	}
	return sig
}

// mustECDSASignature 生成一个 ECDSA（P-256）签名（DER）。
//
// mustECDSASignature produces one ECDSA (P-256) signature in DER form.
func mustECDSASignature(t *testing.T, msg []byte) []byte {
	t.Helper()
	priv, err := GenerateEC("prime256v1")
	if err != nil {
		t.Fatalf("GenerateEC: %v", err)
	}
	sig, err := SignECDSA(priv, msg)
	if err != nil {
		t.Fatalf("ECDSA Sign: %v", err)
	}
	return sig
}
