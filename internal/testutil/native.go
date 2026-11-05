package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BuildNative 编译测试用 EVP 驱动，沿用 CC、CGO_CFLAGS、CGO_LDFLAGS 和铜锁安装目录。
// dir 为调用方创建的临时目录；编译失败返回错误，由调用方断言，不回退到系统 OpenSSL。
//
// BuildNative compiles a test EVP driver using CC, CGO_CFLAGS, CGO_LDFLAGS and TONGSUO_HOME.
// dir is a caller-created temporary directory; compilation errors are returned for caller assertions without an OpenSSL fallback.
func BuildNative(dir, source string) (string, error) {
	root := os.Getenv("TONGSUO_HOME")
	if root == "" {
		root = "/opt/tongsuo"
	}
	cc := strings.Fields(os.Getenv("CC"))
	if len(cc) == 0 {
		cc = []string{"cc"}
	}
	bin := filepath.Join(dir, "evp-driver")
	args := append([]string(nil), cc[1:]...)
	args = append(args, strings.Fields(os.Getenv("CGO_CFLAGS"))...)
	args = append(args, "-I"+filepath.Join(root, "include"), "-Wno-deprecated-declarations", source, "-o", bin)
	args = append(args, strings.Fields(os.Getenv("CGO_LDFLAGS"))...)
	for _, dir := range []string{"lib", "lib64"} {
		path := filepath.Join(root, dir)
		args = append(args, "-L"+path, "-Wl,-rpath,"+path)
	}
	args = append(args, "-lssl", "-lcrypto", "-pthread")
	if out, err := exec.Command(cc[0], args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("compile native driver: %w: %s", err, out)
	}
	return bin, nil
}
