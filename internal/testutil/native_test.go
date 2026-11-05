package testutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildNativeCompilerFailure 验证编译器启动失败以错误返回，保留原始错误供调用方识别。
//
// TestBuildNativeCompilerFailure checks that compiler startup failures return an inspectable wrapped error.
func TestBuildNativeCompilerFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CC", filepath.Join(dir, "missing-compiler"))
	bin, err := BuildNative(dir, "missing-source.c")
	if bin != "" || err == nil {
		t.Fatalf("BuildNative = %q, %v; want empty path and error", bin, err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("compiler error is not preserved: %v", err)
	}
}
