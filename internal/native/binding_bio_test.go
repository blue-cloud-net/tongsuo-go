package native

import "testing"

// TestInputBIOOwnsCopy 验证输入 BIO 持有独立副本并在读完时返回 EOF。
//
// TestInputBIOOwnsCopy verifies that the input BIO owns a copy and reports EOF.
func TestInputBIOOwnsCopy(t *testing.T) {
	input := []byte("PEM input")
	bio := X_BIO_new_input(input)
	if bio == nil {
		t.Fatal("failed to create input BIO")
	}
	defer BIO_free(bio)
	clear(input)
	out := make([]byte, len(input))
	if n := BIO_read(bio, out); n != len(out) || string(out) != "PEM input" {
		t.Fatalf("BIO_read returned %d bytes with unexpected contents", n)
	}
	if n := BIO_read(bio, out); n != 0 {
		t.Fatalf("BIO at EOF returned %d, want 0", n)
	}
}
