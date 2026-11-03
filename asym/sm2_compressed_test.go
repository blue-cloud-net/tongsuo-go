package asym

import (
	"bytes"
	"testing"
)

// TestSM2CompressedCiphertext 验证相关操作的正确性、边界与错误处理。
//
// TestSM2CompressedCiphertext checks operation correctness, boundaries and error handling.
func TestSM2CompressedCiphertext(t *testing.T) {
	key, err := GenerateSM2()
	if err != nil {
		t.Fatal(err)
	}
	defer Close(key)
	plain := []byte("compressed C1")
	for _, order := range []string{"c1c3c2", "c1c2c3"} {
		raw, err := EncryptWithOrder(key.Public(), plain, order)
		if err != nil {
			t.Fatal(err)
		}
		prefix := byte(2) + (raw[64] & 1)
		compressed := append([]byte{prefix}, raw[1:33]...)
		compressed = append(compressed, raw[65:]...)
		der, err := Format(compressed, order, "der")
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(key, der)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("DER compressed decrypt", err)
		}
		got, err = DecryptWithOrder(key, compressed, order)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("compressed decrypt", err)
		}
		expanded, err := Format(der, "der", order)
		if err != nil || !bytes.Equal(expanded, raw) {
			t.Fatal("expanded output changed", err)
		}
		corrupt := append([]byte(nil), compressed...)
		corrupt[len(corrupt)-1] ^= 1
		if _, err := DecryptWithOrder(key, corrupt, order); err == nil {
			t.Fatal("corrupt ciphertext accepted")
		}
	}
	invalid := append([]byte{2}, bytes.Repeat([]byte{0xff}, 64)...)
	if _, err := Format(invalid, "c1c3c2", "der"); err == nil {
		t.Fatal("invalid compressed point accepted")
	}
}
