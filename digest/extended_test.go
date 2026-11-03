package digest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// 标准向量来源：FIPS 202（SHA-3 / SHAKE）与 FIPS 180-4（SHA-512/224、
// SHA-512/256），KECCAK 取以太坊沿用的原始 Keccak-256 空串向量。
//
// Standard vectors: FIPS 202 (SHA-3 / SHAKE) and FIPS 180-4 (SHA-512/224,
// SHA-512/256); KECCAK uses the original Keccak-256 empty-string vector
// used across the Ethereum ecosystem.
var extendedVectors = []struct {
	name string
	in   string
	want string
}{
	{
		"SHA512-224", "abc",
		"4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
	},
	{
		"SHA512-256", "abc",
		"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
	},
	{
		"SHA3-224", "",
		"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
	},
	{
		"SHA3-256", "",
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
	},
	{
		"SHA3-384", "",
		"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
	},
	{
		"SHA3-512", "",
		"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
	},
	{
		"KECCAK-256", "",
		"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
	},
}

// TestExtendedVectors 验证扩展摘要的标准向量（按名 Sum 与类型化入口两条路径）。
//
// TestExtendedVectors verifies the standard vectors for the extended
// digests through both the by-name Sum and the typed entry.
func TestExtendedVectors(t *testing.T) {
	for _, v := range extendedVectors {
		t.Run(v.name, func(t *testing.T) {
			if !Available(v.name) {
				t.Skipf("%s unavailable in this Tongsuo build", v.name)
			}
			want, err := hex.DecodeString(v.want)
			if err != nil {
				t.Fatalf("bad vector: %v", err)
			}
			got, err := Sum(v.name, []byte(v.in))
			if err != nil {
				t.Fatalf("Sum(%q): %v", v.name, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", v.name, got, want)
			}
			if typed := typedSum(v.name, []byte(v.in)); !bytes.Equal(typed, want) {
				t.Errorf("typed %s = %x, want %x", v.name, typed, want)
			}
		})
	}
}

// TestSHAKENeedExplicitLength 验证 SHAKE 必须显式给出输出长度，且长度变化会改变
// 输出前缀（XOF 的可扩展性）。
//
// TestSHAKENeedExplicitLength verifies SHAKE requires an explicit output
// length and that a longer output extends the shorter one.
func TestSHAKENeedExplicitLength(t *testing.T) {
	for _, name := range []string{"SHAKE128", "SHAKE256"} {
		t.Run(name, func(t *testing.T) {
			if !Available(name) {
				t.Skipf("%s unavailable in this Tongsuo build", name)
			}
			if _, err := Sum(name, []byte("abc")); !errors.Is(err, ErrXOFNeedsLength) {
				t.Errorf("Sum(%q) err = %v, want ErrXOFNeedsLength", name, err)
			}
			if _, err := New(name); !errors.Is(err, ErrXOFNeedsLength) {
				t.Errorf("New(%q) err = %v, want ErrXOFNeedsLength", name, err)
			}
		})
	}
}

// TestSHAKE128Vector 验证 SHAKE128 空串 32 字节输出的 FIPS 202 向量。
//
// TestSHAKE128Vector verifies the FIPS 202 vector for a 32-byte SHAKE128
// digest of the empty string.
func TestSHAKE128Vector(t *testing.T) {
	if !Available("SHAKE128") {
		t.Skip("SHAKE128 unavailable in this Tongsuo build")
	}
	got, err := SumSHAKE128(nil, 32)
	if err != nil {
		t.Fatalf("SumSHAKE128: %v", err)
	}
	want, _ := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	if !bytes.Equal(got, want) {
		t.Errorf("SumSHAKE128(empty, 32) = %x, want %x", got, want)
	}
}

// TestSHAKE256Vector 验证 SHAKE256 空串 64 字节输出的 FIPS 202 向量。
//
// TestSHAKE256Vector verifies the FIPS 202 vector for a 64-byte SHAKE256
// digest of the empty string.
func TestSHAKE256Vector(t *testing.T) {
	if !Available("SHAKE256") {
		t.Skip("SHAKE256 unavailable in this Tongsuo build")
	}
	got, err := SumSHAKE256(nil, 64)
	if err != nil {
		t.Fatalf("SumSHAKE256: %v", err)
	}
	want, _ := hex.DecodeString("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")
	if !bytes.Equal(got, want) {
		t.Errorf("SumSHAKE256(empty, 64) = %x, want %x", got, want)
	}
}

// TestSHAKEExtendsPrefix 验证更长输出以更短输出为前缀（XOF 性质）。
//
// TestSHAKEExtendsPrefix verifies a longer output has the shorter one as
// its prefix (the XOF property).
func TestSHAKEExtendsPrefix(t *testing.T) {
	if !Available("SHAKE128") {
		t.Skip("SHAKE128 unavailable in this Tongsuo build")
	}
	short, err := SumSHAKE128([]byte("xof"), 16)
	if err != nil {
		t.Fatalf("SumSHAKE128 short: %v", err)
	}
	long, err := SumSHAKE128([]byte("xof"), 64)
	if err != nil {
		t.Fatalf("SumSHAKE128 long: %v", err)
	}
	if !bytes.Equal(short, long[:16]) {
		t.Errorf("long output does not extend the short one:\n  %x\n  %x", short, long[:16])
	}
	if _, err := SumSHAKE128([]byte("xof"), 0); err == nil {
		t.Error("zero output length: want error")
	}
}

// TestExtendedLengths 验证 Size/BlockSize 与常量一致。
//
// TestExtendedLengths verifies Size and BlockSize match the constants.
func TestExtendedLengths(t *testing.T) {
	cases := []struct {
		name     string
		size     int
		block    int
		skipOn84 bool
	}{
		{"SHA512-224", SHA512_224Size, SHA512_224BlockSize, false},
		{"SHA512-256", SHA512_256Size, SHA512_256BlockSize, false},
		{"SHA3-224", SHA3_224Size, SHA3_224BlockSize, false},
		{"SHA3-256", SHA3_256Size, SHA3_256BlockSize, false},
		{"SHA3-384", SHA3_384Size, SHA3_384BlockSize, false},
		{"SHA3-512", SHA3_512Size, SHA3_512BlockSize, false},
		{"KECCAK-512", KECCAK512Size, KECCAK512BlockSize, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.skipOn84 && !Available(c.name) {
				t.Skipf("%s unavailable in this Tongsuo build", c.name)
			}
			if got, err := Size(c.name); err != nil || got != c.size {
				t.Errorf("Size(%q) = (%d, %v), want %d", c.name, got, err, c.size)
			}
			if got, err := BlockSize(c.name); err != nil || got != c.block {
				t.Errorf("BlockSize(%q) = (%d, %v), want %d", c.name, got, err, c.block)
			}
		})
	}
}

// TestAvailableUnknown 验证未知名返回 false。
//
// TestAvailableUnknown verifies an unknown name reports false.
func TestAvailableUnknown(t *testing.T) {
	if Available("NOPE-256") {
		t.Error("Available(unknown) = true, want false")
	}
	if _, err := Sum("NOPE-256", nil); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("Sum(unknown) err = %v, want ErrUnknownAlgorithm", err)
	}
}
