package meta_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// pemFixture 返回包含两个 PEM 块（证书 + 私钥）与块间噪音的测试输入。
//
// pemFixture returns a payload with two PEM blocks (a certificate and a
// private key) plus noise between them.
func pemFixture(t *testing.T) []byte {
	t.Helper()
	certPEM, err := meta.EncodePEM([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, "CERTIFICATE")
	if err != nil {
		t.Fatalf("EncodePEM(cert): %v", err)
	}
	keyPEM, err := meta.EncodePEM([]byte{0x30, 0x03, 0x02, 0x01, 0x02}, "PRIVATE KEY")
	if err != nil {
		t.Fatalf("EncodePEM(key): %v", err)
	}
	var buf bytes.Buffer
	buf.WriteString("# leading comment, ignored by openssl\n")
	buf.Write(certPEM)
	buf.WriteString("\nsome noise between blocks\n")
	buf.Write(keyPEM)
	return buf.Bytes()
}

// TestSplitPEM 验证多 PEM 块的拆分、顺序与噪音容忍。
//
// TestSplitPEM verifies splitting, ordering and noise tolerance.
func TestSplitPEM(t *testing.T) {
	blocks, err := meta.SplitPEM(pemFixture(t))
	if err != nil {
		t.Fatalf("SplitPEM: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2", len(blocks))
	}
	if blocks[0].Type != "CERTIFICATE" {
		t.Errorf("blocks[0].Type = %q, want CERTIFICATE", blocks[0].Type)
	}
	if blocks[1].Type != "PRIVATE KEY" {
		t.Errorf("blocks[1].Type = %q, want PRIVATE KEY", blocks[1].Type)
	}
}

// TestSplitPEMByType 验证按类型分组与同类型顺序保留。
//
// TestSplitPEMByType verifies grouping by type, preserving order within a
// type.
func TestSplitPEMByType(t *testing.T) {
	first, _ := meta.EncodePEM([]byte{0x01}, "CERTIFICATE")
	second, _ := meta.EncodePEM([]byte{0x02}, "CERTIFICATE")
	payload := append(append([]byte{}, first...), second...)

	byType, err := meta.SplitPEMByType(payload)
	if err != nil {
		t.Fatalf("SplitPEMByType: %v", err)
	}
	certs := byType["CERTIFICATE"]
	if len(certs) != 2 {
		t.Fatalf("got %d certificates, want 2", len(certs))
	}
	if !bytes.Equal(certs[0].Bytes, []byte{0x01}) || !bytes.Equal(certs[1].Bytes, []byte{0x02}) {
		t.Errorf("order not preserved: %x, %x", certs[0].Bytes, certs[1].Bytes)
	}
}

// TestDecodePEMFirst 验证取第一个块；无块时返回 ErrNoPEMBlock。
//
// TestDecodePEMFirst verifies taking the first block and the
// ErrNoPEMBlock error path.
func TestDecodePEMFirst(t *testing.T) {
	der, typ, err := meta.DecodePEMFirst(pemFixture(t))
	if err != nil {
		t.Fatalf("DecodePEMFirst: %v", err)
	}
	if typ != "CERTIFICATE" {
		t.Errorf("type = %q, want CERTIFICATE", typ)
	}
	if !bytes.Equal(der, []byte{0x30, 0x03, 0x02, 0x01, 0x01}) {
		t.Errorf("der = %x", der)
	}

	if _, _, err := meta.DecodePEMFirst([]byte("no pem here")); !errors.Is(err, meta.ErrNoPEMBlock) {
		t.Errorf("plain text: err = %v, want ErrNoPEMBlock", err)
	}
	if _, err := meta.SplitPEM(nil); !errors.Is(err, meta.ErrNoPEMBlock) {
		t.Errorf("empty input: err = %v, want ErrNoPEMBlock", err)
	}
}

// TestEncodePEM 验证编码形态与空输入错误。
//
// TestEncodePEM verifies the encoding shape and the empty-input error.
func TestEncodePEM(t *testing.T) {
	out, err := meta.EncodePEM([]byte{0xde, 0xad, 0xbe, 0xef}, "X509 CRL")
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("-----BEGIN X509 CRL-----")) {
		t.Errorf("missing BEGIN header: %q", out)
	}
	if !bytes.HasSuffix(out, []byte("-----END X509 CRL-----\n")) {
		t.Errorf("missing END header: %q", out)
	}
	if _, err := meta.EncodePEM(nil, "CERTIFICATE"); err == nil {
		t.Error("empty der: want error")
	}
}

// TestSplitPEMRoundTrip 验证 EncodePEM → SplitPEM 往返。
//
// TestSplitPEMRoundTrip verifies the EncodePEM → SplitPEM round trip.
func TestSplitPEMRoundTrip(t *testing.T) {
	der := bytes.Repeat([]byte{0xa5}, 200)
	encoded, err := meta.EncodePEM(der, "CERTIFICATE")
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	blocks, err := meta.SplitPEM(encoded)
	if err != nil {
		t.Fatalf("SplitPEM: %v", err)
	}
	if len(blocks) != 1 || !bytes.Equal(blocks[0].Bytes, der) {
		t.Fatalf("round trip mismatch: %d blocks", len(blocks))
	}
}
