package core

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestDigestMetadata 验证各摘要描述符的 Size/BlockSize 缓存正确。
func TestDigestMetadata(t *testing.T) {
	tests := []struct {
		name    string
		digest  *Digest
		size    int
		block   int
		wantNil bool
	}{
		{"SM3", SM3(), 32, 64, false},
		{"MD5", MD5(), 16, 64, false},
		{"SHA1", SHA1(), 20, 64, false},
		{"SHA224", SHA224(), 28, 64, false},
		{"SHA256", SHA256(), 32, 64, false},
		{"SHA384", SHA384(), 48, 128, false},
		{"SHA512", SHA512(), 64, 128, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.digest == nil && !tt.wantNil {
				t.Fatalf("%s returned nil", tt.name)
			}
			if got := tt.digest.Size(); got != tt.size {
				t.Errorf("Size = %d, want %d", got, tt.size)
			}
			if got := tt.digest.BlockSize(); got != tt.block {
				t.Errorf("BlockSize = %d, want %d", got, tt.block)
			}
		})
	}
}

// TestDigestOneShot 验证 OneShot 对各种摘要返回正确长度。
func TestDigestOneShot(t *testing.T) {
	data := []byte("hello digest")
	tests := []struct {
		name   string
		digest *Digest
		size   int
	}{
		{"SM3", SM3(), 32},
		{"MD5", MD5(), 16},
		{"SHA256", SHA256(), 32},
		{"SHA512", SHA512(), 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.digest.OneShot(data)
			if err != nil {
				t.Fatalf("OneShot: %v", err)
			}
			if len(out) != tt.size {
				t.Errorf("OneShot output length = %d, want %d", len(out), tt.size)
			}
		})
	}
}

// TestDigestStreamingVsOneShot 验证 Update+Final 与 OneShot 结果一致。
func TestDigestStreamingVsOneShot(t *testing.T) {
	data := []byte("streaming vs one-shot equivalence test data")
	for _, name := range []string{"SM3", "MD5", "SHA1", "SHA256", "SHA512"} {
		t.Run(name, func(t *testing.T) {
			var d *Digest
			switch name {
			case "SM3":
				d = SM3()
			case "MD5":
				d = MD5()
			case "SHA1":
				d = SHA1()
			case "SHA256":
				d = SHA256()
			case "SHA512":
				d = SHA512()
			}

			oneShot, err := d.OneShot(data)
			if err != nil {
				t.Fatalf("OneShot: %v", err)
			}

			ctx, err := NewDigestCtx(d)
			if err != nil {
				t.Fatalf("NewDigestCtx: %v", err)
			}
			defer ctx.Close()

			mid := len(data) / 2
			if err := ctx.Update(data[:mid]); err != nil {
				t.Fatalf("Update[:mid]: %v", err)
			}
			if err := ctx.Update(data[mid:]); err != nil {
				t.Fatalf("Update[mid:]: %v", err)
			}
			streaming, err := ctx.Final()
			if err != nil {
				t.Fatalf("Final: %v", err)
			}
			if !bytes.Equal(oneShot, streaming) {
				t.Fatalf("%s: streaming and one-shot differ\noneShot=%x\nstream =%x", name, oneShot, streaming)
			}
		})
	}
}

// TestDigestSumNonDestructive 验证 Sum 不改变 ctx 状态，Final 之后仍可用。
func TestDigestSumNonDestructive(t *testing.T) {
	ctx, err := NewDigestCtx(SM3())
	if err != nil {
		t.Fatalf("NewDigestCtx: %v", err)
	}
	defer ctx.Close()

	data := []byte("sum is non-destructive")
	if err := ctx.Update(data); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// 第一次 Sum
	sum1, err := ctx.Sum()
	if err != nil {
		t.Fatalf("Sum 1: %v", err)
	}
	// 第二次 Sum 应与第一次一致（未变更）
	sum2, err := ctx.Sum()
	if err != nil {
		t.Fatalf("Sum 2: %v", err)
	}
	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("Sum is destructive: %x != %x", sum1, sum2)
	}

	// Final 也应与 Sum 一致
	final, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if !bytes.Equal(sum1, final) {
		t.Fatalf("Final differs from Sum: %x != %x", final, sum1)
	}
}

// TestDigestReset 验证 Reset 后再次计算结果一致。
func TestDigestReset(t *testing.T) {
	ctx, err := NewDigestCtx(SHA256())
	if err != nil {
		t.Fatalf("NewDigestCtx: %v", err)
	}
	defer ctx.Close()

	data := []byte("test data for reset")
	if err := ctx.Update(data); err != nil {
		t.Fatalf("Update: %v", err)
	}
	first, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if err := ctx.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := ctx.Update(data); err != nil {
		t.Fatalf("Update 2: %v", err)
	}
	second, err := ctx.Final()
	if err != nil {
		t.Fatalf("Final 2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("Reset not idempotent: %x != %x", first, second)
	}
}

// TestDigestClosedContext 验证关闭后 ctx 的方法返回错误。
func TestDigestClosedContext(t *testing.T) {
	ctx, err := NewDigestCtx(SM3())
	if err != nil {
		t.Fatalf("NewDigestCtx: %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ctx.Update([]byte("x")); err == nil {
		t.Fatal("Update on closed should error")
	}
	if _, err := ctx.Sum(); err == nil {
		t.Fatal("Sum on closed should error")
	}
	if _, err := ctx.Final(); err == nil {
		t.Fatal("Final on closed should error")
	}
	if err := ctx.Reset(); err == nil {
		t.Fatal("Reset on closed should error")
	}
}

// TestDigestUniqueForDifferentInputs 验证不同输入产生不同摘要。
func TestDigestUniqueForDifferentInputs(t *testing.T) {
	a := []byte("message A")
	b := []byte("message B")
	aHash, _ := SHA256().OneShot(a)
	bHash, _ := SHA256().OneShot(b)
	if bytes.Equal(aHash, bHash) {
		t.Fatal("SHA256 produced same hash for different inputs")
	}
}

// TestDigestRandomData 验证对随机数据 OneShot 不 panic。
func TestDigestRandomData(t *testing.T) {
	rng := make([]byte, 1024)
	if _, err := rand.Read(rng); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	for _, d := range []*Digest{SM3(), SHA256(), SHA512()} {
		if _, err := d.OneShot(rng); err != nil {
			t.Fatalf("OneShot: %v", err)
		}
	}
}
