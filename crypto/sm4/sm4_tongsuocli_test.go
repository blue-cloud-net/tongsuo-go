//go:build tongsuocli

package sm4

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIEncryptECB 与铜锁 openssl enc -sm4-ecb（PKCS7 填充）对比。
func TestCLIEncryptECB(t *testing.T) {
	key := vectorKey
	plain := bytes.Repeat([]byte("tongsuo-cli"), 8) // 88 字节，非块对齐

	ct, err := EncryptECB(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := testutil.RunOpenSSL([]string{
		"enc", "-sm4-ecb", "-K", hex.EncodeToString(key), "-e",
	}, plain)
	if err != nil {
		t.Fatalf("openssl enc: %v", err)
	}
	if !bytes.Equal(ct, out) {
		t.Fatalf("ECB cli mismatch: got %x want %x", ct, out)
	}
}

// TestCLIEncryptCBC 与铜锁 openssl enc -sm4-cbc（PKCS7 填充）对比。
func TestCLIEncryptCBC(t *testing.T) {
	key := vectorKey
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	plain := bytes.Repeat([]byte("tongsuo-cli"), 8)

	ct, err := EncryptCBC(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := testutil.RunOpenSSL([]string{
		"enc", "-sm4-cbc", "-K", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(iv), "-e",
	}, plain)
	if err != nil {
		t.Fatalf("openssl enc: %v", err)
	}
	if !bytes.Equal(ct, out) {
		t.Fatalf("CBC cli mismatch: got %x want %x", ct, out)
	}
}
