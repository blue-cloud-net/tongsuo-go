//go:build tongsuocli

package aes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestCLIECB 与铜锁 openssl enc -aes-128-ecb（PKCS7 填充）对比。
func TestCLIECB(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	plain := bytes.Repeat([]byte("aes-cli-data"), 8)
	ct, err := EncryptECB(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := testutil.RunOpenSSL([]string{
		"enc", "-aes-128-ecb", "-K", hex.EncodeToString(key), "-e",
	}, plain)
	if err != nil {
		t.Fatalf("openssl enc: %v", err)
	}
	if !bytes.Equal(ct, out) {
		t.Fatalf("ECB cli mismatch")
	}
}

// TestCLICBC 与铜锁 openssl enc -aes-256-cbc 对比。
func TestCLICBC(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, 32)
	iv := bytes.Repeat([]byte{0x11}, BlockSize)
	plain := bytes.Repeat([]byte("aes-cli-data"), 8)
	ct, err := EncryptCBC(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := testutil.RunOpenSSL([]string{
		"enc", "-aes-256-cbc", "-K", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(iv), "-e",
	}, plain)
	if err != nil {
		t.Fatalf("openssl enc: %v", err)
	}
	if !bytes.Equal(ct, out) {
		t.Fatalf("CBC cli mismatch")
	}
}

// TestCLICTR 与铜锁 openssl enc -aes-128-ctr 对比（流模式，无填充）。
func TestCLICTR(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 16)
	iv := bytes.Repeat([]byte{0x22}, BlockSize)
	plain := bytes.Repeat([]byte("aes-cli-data"), 8)
	ct, err := EncryptCTR(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := testutil.RunOpenSSL([]string{
		"enc", "-aes-128-ctr", "-K", hex.EncodeToString(key),
		"-iv", hex.EncodeToString(iv), "-e", "-nopad",
	}, plain)
	if err != nil {
		t.Fatalf("openssl enc: %v", err)
	}
	if !bytes.Equal(ct, out) {
		t.Fatalf("CTR cli mismatch")
	}
}
