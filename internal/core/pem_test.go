package core

import (
	"encoding/pem"
	"testing"
)

// TestDecodeLeadingPEM 验证严格读取不会跳过之前的畸形块。
//
// TestDecodeLeadingPEM verifies strict parsing does not skip malformed leading blocks.
func TestDecodeLeadingPEM(t *testing.T) {
	good := pem.EncodeToMemory(&pem.Block{Type: "TEST", Bytes: []byte("fixture")})
	two := append(append([]byte(nil), good...), good...)
	b, rest, err := DecodeLeadingPEM(two)
	if err != nil || b == nil || len(rest) != len(good) {
		t.Fatal("valid PEM sequence did not return its first block")
	}
	bad := append([]byte("-----BEGIN TEST-----\nbad-block\n"), good...)
	if _, _, err := DecodeLeadingPEM(bad); err == nil {
		t.Fatal("skipped an invalid first PEM block")
	}
}
