// Package testutil 的同包单元测试（覆盖 openssl CLI 定位辅助）。
// Unit tests for the openssl CLI location helpers in testutil.
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFake 在 dir 下写一个文件并返回路径。
//
// writeFake writes a file under dir with the given mode and returns its path.
func writeFake(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestOpenSSLBin 验证环境变量优先、缺失时回退到 defaultBin。
//
// TestOpenSSLBin verifies TONGSUO_OPENSSL_BIN takes precedence and that an
// empty value falls back to defaultBin.
func TestOpenSSLBin(t *testing.T) {
	t.Setenv("TONGSUO_OPENSSL_BIN", "/custom/openssl")
	if got := OpenSSLBin(); got != "/custom/openssl" {
		t.Fatalf("OpenSSLBin() = %q, want /custom/openssl", got)
	}
	t.Setenv("TONGSUO_OPENSSL_BIN", "")
	if got := OpenSSLBin(); got != defaultBin {
		t.Fatalf("OpenSSLBin() fallback = %q, want %q", got, defaultBin)
	}
}

// TestOpenSSLAvailable 验证可用性判断：可执行文件为 true，目录 / 缺失 / 不可执行均为 false。
//
// TestOpenSSLAvailable verifies the availability probe: an executable file is
// true, while a directory, a missing path and a non-executable file are false.
func TestOpenSSLAvailable(t *testing.T) {
	dir := t.TempDir()

	exec := writeFake(t, dir, "openssl", 0o755)
	t.Setenv("TONGSUO_OPENSSL_BIN", exec)
	if !OpenSSLAvailable() {
		t.Fatal("OpenSSLAvailable() = false for an executable file")
	}

	t.Setenv("TONGSUO_OPENSSL_BIN", dir)
	if OpenSSLAvailable() {
		t.Fatal("OpenSSLAvailable() = true for a directory")
	}

	t.Setenv("TONGSUO_OPENSSL_BIN", filepath.Join(dir, "missing"))
	if OpenSSLAvailable() {
		t.Fatal("OpenSSLAvailable() = true for a missing path")
	}

	plain := writeFake(t, dir, "not-exec", 0o644)
	t.Setenv("TONGSUO_OPENSSL_BIN", plain)
	if OpenSSLAvailable() {
		t.Fatal("OpenSSLAvailable() = true for a non-executable file")
	}
}

// TestSkipIfNoOpenSSLReturnsBin 验证 CLI 可用时返回其路径（不可用分支会直接跳过测试，
// 无法在同一用例内断言）。
//
// TestSkipIfNoOpenSSLReturnsBin verifies the helper returns the CLI path when
// the binary is available; the unavailable branch skips the test itself and
// therefore cannot be asserted from within the same case.
func TestSkipIfNoOpenSSLReturnsBin(t *testing.T) {
	dir := t.TempDir()
	exec := writeFake(t, dir, "openssl", 0o755)
	t.Setenv("TONGSUO_OPENSSL_BIN", exec)
	if got := SkipIfNoOpenSSL(t); got != exec {
		t.Fatalf("SkipIfNoOpenSSL() = %q, want %q", got, exec)
	}
}

// TestRunOpenSSLMissingBinary 验证 CLI 缺失时 RunOpenSSL 返回错误（而非 panic）。
//
// TestRunOpenSSLMissingBinary verifies RunOpenSSL returns an error instead of
// panicking when the CLI is missing.
func TestRunOpenSSLMissingBinary(t *testing.T) {
	t.Setenv("TONGSUO_OPENSSL_BIN", filepath.Join(t.TempDir(), "missing-openssl"))
	if out, err := RunOpenSSL([]string{"version"}, nil); err == nil {
		t.Fatalf("RunOpenSSL with a missing binary: out = %q, err = nil", out)
	}
}
