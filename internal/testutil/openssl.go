// Package testutil 提供测试共享工具（铜锁 openssl CLI 封装、标准向量加载等）。
//
// 本包仅供测试使用，位于 internal 目录，禁止被库外部导入。
//
// Package testutil provides shared testing helpers, including a Tongsuo
// openssl CLI wrapper and standard-vector loaders. The package is for
// tests only, lives under internal/ and must not be imported outside
// the library.
package testutil

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// defaultBin 是 OpenSSLBin 在环境变量缺失时使用的默认回退路径。
//
// defaultBin is the fallback path OpenSSLBin uses when the environment
// variable is unset or empty.
const defaultBin = "/opt/tongsuo/bin/openssl"

// OpenSSLBin 返回铜锁 openssl 可执行文件路径。
// 优先使用环境变量 TONGSUO_OPENSSL_BIN，否则回退到 defaultBin。
//
// OpenSSLBin returns the path to the Tongsuo openssl executable. It
// prefers the TONGSUO_OPENSSL_BIN environment variable and falls back to
// defaultBin when the variable is empty or unset.
func OpenSSLBin() string {
	if p := os.Getenv("TONGSUO_OPENSSL_BIN"); p != "" {
		return p
	}
	return defaultBin
}

// RunOpenSSL 调用铜锁 openssl 命令，将 stdin 作为输入，返回 stdout。
// 参数顺序遵循 openssl 命令行约定；本函数不包含任何断言逻辑。
//
// RunOpenSSL invokes the Tongsuo openssl command with the supplied
// arguments, feeding stdin and returning stdout. The argument order
// follows openssl CLI conventions; no assertions are performed and the
// returned error is whatever the underlying exec.Cmd.Output produces.
func RunOpenSSL(args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(OpenSSLBin(), args...)
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.Output()
}

// RunOpenSSLCombined 调用铜锁 openssl 命令并返回**合并输出**（stdout + stderr）。
// 与 RunOpenSSL 的差别是保留 stderr —— `openssl verify` / `crl -verify` 一类子命令的
// 结果信息写在 stderr；本函数不含任何断言逻辑。
//
// RunOpenSSLCombined invokes the Tongsuo openssl command and returns its
// combined output (stdout + stderr). Unlike RunOpenSSL it keeps stderr, which
// subcommands such as `openssl verify` and `crl -verify` write their result to.
// No assertions are performed.
func RunOpenSSLCombined(args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(OpenSSLBin(), args...)
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.CombinedOutput()
}

// RunOpenSSLCombinedIn 等同 RunOpenSSLCombined，但在 dir 目录下执行进程。
// openssl 的 ca / ocsp / crl 等子命令依赖目录内的相对路径配置，必须指定工作目录。
//
// RunOpenSSLCombinedIn is RunOpenSSLCombined with the process working directory
// set to dir. Subcommands such as ca / ocsp / crl rely on relative paths inside
// that directory, so the working directory must be set explicitly.
func RunOpenSSLCombinedIn(dir string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(OpenSSLBin(), args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.CombinedOutput()
}

// MustRunOpenSSL 在铜锁 CLI 可用时运行 openssl 并返回合并输出；CLI 缺失则跳过当前
// 测试，命令失败则用 t.Fatalf 报错（错误信息含合并输出）。对拍测试的统一入口。
//
// MustRunOpenSSL runs openssl when the Tongsuo CLI is available and returns the
// combined output. It skips the current test when the CLI is missing and fails it
// with t.Fatalf (including the combined output) when the command exits non-zero.
// This is the single entry point for interop tests.
func MustRunOpenSSL(t *testing.T, args ...string) []byte {
	t.Helper()
	SkipIfNoOpenSSL(t)
	out, err := RunOpenSSLCombined(args, nil)
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// MustRunOpenSSLInDir 等同 MustRunOpenSSL，但在 dir 目录下执行进程。
//
// MustRunOpenSSLInDir is MustRunOpenSSL with the process working directory set
// to dir.
func MustRunOpenSSLInDir(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	SkipIfNoOpenSSL(t)
	out, err := RunOpenSSLCombinedIn(dir, args, nil)
	if err != nil {
		t.Fatalf("openssl %v: %v\n%s", args, err, out)
	}
	return out
}

// OpenSSLAvailable 报告 OpenSSLBin 返回的路径是否存在且可执行。
// 供 tongsuocli 对比测试在缺少铜锁 CLI 时安全跳过（OpenSSLBin 永远不会返回
// 空串，因此不能靠空串判断）。
//
// OpenSSLAvailable reports whether the path returned by OpenSSLBin points
// at an existing executable. It lets tongsuocli interop tests skip safely
// when the Tongsuo CLI is missing, because OpenSSLBin never returns an
// empty string and therefore cannot be tested for emptiness.
func OpenSSLAvailable() bool {
	info, err := os.Stat(OpenSSLBin())
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0o111 != 0
}

// SkipIfNoOpenSSL 在铜锁 openssl CLI 不可用时跳过当前测试，否则返回其路径。
//
// SkipIfNoOpenSSL skips the current test when the Tongsuo openssl CLI is
// unavailable and otherwise returns its path (same value as OpenSSLBin).
func SkipIfNoOpenSSL(t *testing.T) string {
	t.Helper()
	bin := OpenSSLBin()
	if !OpenSSLAvailable() {
		t.Skipf("Tongsuo openssl CLI not found at %q; set TONGSUO_OPENSSL_BIN or install Tongsuo", bin)
	}
	return bin
}
