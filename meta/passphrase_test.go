package meta

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPassphraseLiteral 验证明文口令来源。
//
// TestPassphraseLiteral verifies the literal passphrase source.
func TestPassphraseLiteral(t *testing.T) {
	p, err := NewPassphrase("pass:secret")
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	if got := string(p.Bytes()); got != "secret" {
		t.Errorf("Bytes = %q, want %q", got, "secret")
	}
	if p.IsEmpty() {
		t.Error("IsEmpty = true, want false")
	}
}

// TestPassphraseWithoutPrefix 验证无前缀时按明文处理。
//
// TestPassphraseWithoutPrefix verifies that a specification without a
// prefix is taken literally.
func TestPassphraseWithoutPrefix(t *testing.T) {
	p, err := NewPassphrase("bare-secret")
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	if got := string(p.Bytes()); got != "bare-secret" {
		t.Errorf("Bytes = %q, want %q", got, "bare-secret")
	}
}

// TestPassphraseEnv 验证环境变量来源。
//
// TestPassphraseEnv verifies the environment-variable source.
func TestPassphraseEnv(t *testing.T) {
	const name = "TONGSUO_GO_TEST_PASSPHRASE"
	t.Setenv(name, "from-env")
	p, err := NewPassphrase("env:" + name)
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	if got := string(p.Bytes()); got != "from-env" {
		t.Errorf("Bytes = %q, want %q", got, "from-env")
	}
}

// TestPassphraseEnvUnset 验证未设置的环境变量被拒绝。
//
// TestPassphraseEnvUnset verifies that an unset environment variable is
// rejected.
func TestPassphraseEnvUnset(t *testing.T) {
	const name = "TONGSUO_GO_TEST_PASSPHRASE_MISSING"
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	if _, err := NewPassphrase("env:" + name); err == nil {
		t.Fatal("NewPassphrase: expected error for unset environment variable")
	}
}

// TestPassphraseFile 验证文件来源会去掉末尾换行。
//
// TestPassphraseFile verifies that the file source strips the trailing
// newline.
func TestPassphraseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	p, err := NewPassphrase("file:" + path)
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	if got := string(p.Bytes()); got != "file-secret" {
		t.Errorf("Bytes = %q, want %q", got, "file-secret")
	}
}

// TestPassphraseFD 验证文件描述符来源。
//
// TestPassphraseFD verifies the file-descriptor source.
func TestPassphraseFD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(path, []byte("fd-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	p, err := NewPassphrase("fd:" + strconv.FormatUint(uint64(f.Fd()), 10))
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	if got := string(p.Bytes()); got != "fd-secret" {
		t.Errorf("Bytes = %q, want %q", got, "fd-secret")
	}
}

// TestPassphraseUnknownScheme 验证未知来源前缀被拒绝。
//
// TestPassphraseUnknownScheme verifies that an unknown source prefix is
// rejected.
func TestPassphraseUnknownScheme(t *testing.T) {
	if _, err := NewPassphrase("rot13:abc"); err == nil {
		t.Fatal("NewPassphrase: expected error for unknown source")
	}
}

// TestPassphraseStringIsRedacted 验证 String() 不泄露口令内容。
//
// TestPassphraseStringIsRedacted verifies that String never leaks the
// passphrase content.
func TestPassphraseStringIsRedacted(t *testing.T) {
	p, err := NewPassphrase("pass:super-secret-value")
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	if strings.Contains(p.String(), "super-secret-value") {
		t.Fatalf("String() leaked the passphrase: %q", p.String())
	}
	if p.String() == "" {
		t.Error("String() returned an empty description")
	}
}

// TestPassphraseNil 验证 nil 口令的安全行为。
//
// TestPassphraseNil verifies the safe behaviour of a nil passphrase.
func TestPassphraseNil(t *testing.T) {
	var p *Passphrase
	if p.Bytes() != nil {
		t.Error("Bytes on a nil passphrase should be nil")
	}
	if p.String() != "" {
		t.Error("String on a nil passphrase should be empty")
	}
	if !p.IsEmpty() {
		t.Error("IsEmpty on a nil passphrase should be true")
	}
}
