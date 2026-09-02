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
)

// OpenSSLBin 返回铜锁 openssl 可执行文件路径。
// 优先使用环境变量 TONGSUO_OPENSSL_BIN，否则默认 /opt/tongsuo/bin/openssl。
//
// OpenSSLBin returns the path to the Tongsuo openssl executable. It
// prefers the TONGSUO_OPENSSL_BIN environment variable and falls back
// to /opt/tongsuo/bin/openssl when the variable is empty or unset.
func OpenSSLBin() string {
	if p := os.Getenv("TONGSUO_OPENSSL_BIN"); p != "" {
		return p
	}
	return "/opt/tongsuo/bin/openssl"
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
