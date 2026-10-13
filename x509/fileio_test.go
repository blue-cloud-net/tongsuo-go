package x509

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestCertificatePEMFileIO 验证证书的 PEM 文件读写往返。
//
// TestCertificatePEMFileIO verifies the PEM file round trip for certificates.
func TestCertificatePEMFileIO(t *testing.T) {
	priv, err := asym.GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	subject := NewName().Add("CN", "file.example.com")
	cert, err := CreateCertificate(subject, subject, 77,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cert.Close() })

	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := SaveCertificatePEMFile(path, cert, 0o644); err != nil {
		t.Fatalf("SaveCertificatePEMFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("file perm = %v, want 0644", perm)
	}

	loaded, err := LoadCertificatePEMFile(path)
	if err != nil {
		t.Fatalf("LoadCertificatePEMFile: %v", err)
	}
	t.Cleanup(func() { _ = loaded.Close() })
	if loaded.Subject() != "file.example.com" {
		t.Errorf("loaded subject = %q", loaded.Subject())
	}
	if err := loaded.Verify(priv.Public()); err != nil {
		t.Errorf("verify loaded from file: %v", err)
	}

	// 覆写
	if err := SaveCertificatePEMFile(path, loaded, 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("overwritten perm = %v, want 0600", perm)
	}

	// 错误路径
	if err := SaveCertificatePEMFile(path, nil, 0o600); err == nil {
		t.Error("nil certificate should fail")
	}
	_, err = LoadCertificatePEMFile(filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil {
		t.Error("missing file should fail")
	} else if !strings.Contains(err.Error(), "x509:") {
		t.Errorf("error should carry context, got %v", err)
	}
	// 内容非 PEM
	badPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificatePEMFile(badPath); err == nil {
		t.Error("non-PEM content should fail")
	}
}
