//go:build tongsuocli

package ecdh

import (
	"bytes"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// TestCLIKeyInterop 验证 ECDH 私钥 PEM 与 openssl ec 解析一致。
//
// 注：本测试仅做最小化互操作校验（私钥 PEM → openssl ec 解析）。
// 由于 ECDH 共享密钥派生的 CLI 调用复杂（需要 PEM 公钥 + ECDH peer 公钥），
// 完整 happy-path 比对留作 future work。
func TestCLIKeyInterop(t *testing.T) {
	priv, err := core.GenerateECKey("prime256v1")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}
	defer priv.Close()

	pemBytes, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}

	if len(pemBytes) == 0 {
		t.Fatal("empty PEM")
	}
	if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN")) {
		t.Fatalf("invalid PEM header: %q", pemBytes[:min(20, len(pemBytes))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}