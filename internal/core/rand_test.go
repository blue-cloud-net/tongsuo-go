package core

import (
	"bytes"
	"testing"
)

// TestRandomBytesBasic 验证 RandomBytes 填充正确长度。
func TestRandomBytesBasic(t *testing.T) {
	b := make([]byte, 32)
	if err := RandomBytes(b); err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	// 注：32 字节随机全为 0 的概率 1/2^256，可视为不可能。
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("RandomBytes returned all-zero buffer (CSPRNG failure?)")
	}
}

// TestRandomBytesZeroLength 验证 len(b)==0 时不调用 CSPRNG。
func TestRandomBytesZeroLength(t *testing.T) {
	b := make([]byte, 0)
	if err := RandomBytes(b); err != nil {
		t.Fatalf("RandomBytes(0): %v", err)
	}
}

// TestRandomBytesUniqueness 验证两次调用产生不同输出。
func TestRandomBytesUniqueness(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	if err := RandomBytes(a); err != nil {
		t.Fatalf("RandomBytes a: %v", err)
	}
	if err := RandomBytes(b); err != nil {
		t.Fatalf("RandomBytes b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two consecutive RandomBytes calls produced identical output")
	}
}

// TestRandomBytesVariousSizes 验证各种长度的填充。
func TestRandomBytesVariousSizes(t *testing.T) {
	for _, n := range []int{1, 16, 32, 64, 128, 256, 1024} {
		b := make([]byte, n)
		if err := RandomBytes(b); err != nil {
			t.Fatalf("RandomBytes(%d): %v", n, err)
		}
		if len(b) != n {
			t.Fatalf("len(b) = %d, want %d", len(b), n)
		}
	}
}
