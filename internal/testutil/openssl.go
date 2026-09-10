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
