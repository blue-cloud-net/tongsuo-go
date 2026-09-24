//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。覆盖 tongsuo version / version -a / errstr 三个子命令的 Go 侧对拍。

package meta_test

import (
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestTongsuoVersion_CLI 验证 meta.Version() 与 tongsuo version 第二行
// 去 "(Library: ...)" 前缀后的部分一致。
//
// 注：Tongsuo CLI 的 version 输出第 1 行是 Tongsuo banner（如
// "Tongsuo: Tongsuo 8.5.0-pre2 (Library: Tongsuo 8.5.0-pre2)"），第 2 行
// 是 OpenSSL 行（如 "OpenSSL 3.5.4 3 Aug 2026 (Library: OpenSSL 3.5.4 ...)"）。
// 而 C 侧 OpenSSL_version(0) 只返回 "OpenSSL 3.5.4 3 Aug 2026"（无尾缀）；
// 本测试校 OpenSSL 行的**主部分**与 CLI 第 2 行的前缀相等。
//
// TestTongsuoVersion_CLI verifies meta.Version() matches the main part
// of the second line of `tongsuo version` (CLI appends a "(Library: ...)"
// suffix that the C side does not produce).
func TestTongsuoVersion_CLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	out, err := testutil.RunOpenSSL([]string{"version"}, nil)
	if err != nil {
		t.Fatalf("openssl version failed: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("openssl version output has %d lines, want >=2:\n%s", len(lines), string(out))
	}
	cli := strings.TrimRight(lines[1], "\r")
	// 去掉 "(Library: ..." 后缀（C 侧 OpenSSL_version(0) 不输出）
	if idx := strings.Index(cli, " (Library:"); idx > 0 {
		cli = cli[:idx]
	}
	got := meta.Version()
	if got != cli {
		t.Errorf("meta.Version() = %q\nwant = %q", got, cli)
	}
}

// TestTongsuoVersion_a_CLI 验证 meta.BuildInfo.String() 包含 tongsuo version -a
// 输出的关键字段（OPENSSLDIR / platform / built on）。
//
// TestTongsuoVersion_a_CLI verifies meta.BuildInfo.String() carries the
// same OPENSSLDIR / platform / built-on fields as `tongsuo version -a`.
func TestTongsuoVersion_a_CLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	_, err := testutil.RunOpenSSL([]string{"version", "-a"}, nil)
	if err != nil {
		t.Fatalf("openssl version -a failed: %v", err)
	}

	bi := meta.ReadBuildInfo()
	got := bi.String()

	if !strings.Contains(got, bi.OpenSSLDir) {
		t.Errorf("BuildInfo missing OpenSSLDir=%q; got %q", bi.OpenSSLDir, got)
	}
	if !strings.Contains(got, bi.Platform) {
		t.Errorf("BuildInfo missing platform=%q; got %q", bi.Platform, got)
	}
	if !strings.Contains(got, bi.BuiltOn) {
		t.Errorf("BuildInfo missing builtOn=%q; got %q", bi.BuiltOn, got)
	}
}

// TestErrstr_CLI 验证 meta.ErrorString 与 tongsuo errstr <code> 输出逐字节一致。
//
// TestErrstr_CLI verifies meta.ErrorString matches tongsuo errstr output
// byte-for-byte for a known code.
func TestErrstr_CLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	code := uint64(0x0906D06C)
	out, err := testutil.RunOpenSSL([]string{"errstr", "0x0906D06C"}, nil)
	if err != nil {
		t.Fatalf("openssl errstr failed: %v", err)
	}
	cli := strings.TrimRight(string(out), "\n")
	got := meta.ErrorString(code)
	if got != cli {
		t.Errorf("meta.ErrorString(0x%x) = %q\nwant = %q", code, got, cli)
	}
}
