package mac

import (
	"bytes"
	"encoding/hex"
	"hash"
	"testing"
)

// TestHMACKnownVectors 用铜锁 CLI 实测取得的向量验证 7 种 HMAC。
// key = 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07，data = "abc"。
func TestHMACKnownVectors(t *testing.T) {
	key, _ := hex.DecodeString("0001020304050607")
	data := []byte("abc")

	vectors := []struct {
		name string
		want string
	}{
		{"HMAC-SM3", "D3586FA146DFD27A8F39152121541CDAC7727B0D434521351EDDC7E4A17C7155"},
		{"HMAC-MD5", "4DD165B813CFE2016DC3A0C77DE5EABB"},
		{"HMAC-SHA1", "08C144A77878D70A064B82617EEA906D98A54544"},
		{"HMAC-SHA224", "A512D16E3316E173605D4FFF52594141A63186664EF054A635727FB5"},
		{"HMAC-SHA256", "D639301952B492E23D24BE078F62922F9A890E85D6753FD6C3CD5372B35A2326"},
		{"HMAC-SHA384", "17830995892E761FC7D8D1BC911896C06C97A86B1AD496A072101B4491253FE7CB9EE46007EC047FE9AA9BE1D70D4A6A"},
		{"HMAC-SHA512", "004385DDDB2730CF78AC13EAA2243DFC5E18268527EB8EBF783906F5655E013FD3CCBAFFB5754CF7E65141CD2A331E99EE1D8BDAA2B01CEEB0B6A09A8575DF89"},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got := typedSum(v.name, key, data)
			want, err := hex.DecodeString(v.want)
			if err != nil {
				t.Fatalf("bad want hex: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Sum%s = %x, want %s", v.name, got, v.want)
			}
		})
	}
}

// TestHMACTagLengths 验证 7 种 HMAC 标签字节长度。
func TestHMACTagLengths(t *testing.T) {
	key := []byte("k")
	data := []byte("d")
	cases := []struct {
		name string
		size int
		sum  func([]byte, []byte) []byte
	}{
		{"HMAC-SM3", 32, SumHMACSM3},
		{"HMAC-MD5", 16, SumHMACMD5},
		{"HMAC-SHA1", 20, SumHMACSHA1},
		{"HMAC-SHA224", 28, SumHMACSHA224},
		{"HMAC-SHA256", 32, SumHMACSHA256},
		{"HMAC-SHA384", 48, SumHMACSHA384},
		{"HMAC-SHA512", 64, SumHMACSHA512},
	}
	for _, c := range cases {
		tag := c.sum(key, data)
		if len(tag) != c.size {
			t.Errorf("%s tag len = %d, want %d", c.name, len(tag), c.size)
		}
	}
}

// TestNewHMACSmoke 验证 7 种 NewHMAC* 流式与一次性助手结果一致。
func TestNewHMACSmoke(t *testing.T) {
	key := []byte("the key")
	data := []byte("the data")
	cases := []struct {
		name string
		new  func([]byte) hash.Hash
		sum  func([]byte, []byte) []byte
	}{
		{"HMAC-SM3", NewHMACSM3, SumHMACSM3},
		{"HMAC-MD5", NewHMACMD5, SumHMACMD5},
		{"HMAC-SHA1", NewHMACSHA1, SumHMACSHA1},
		{"HMAC-SHA224", NewHMACSHA224, SumHMACSHA224},
		{"HMAC-SHA256", NewHMACSHA256, SumHMACSHA256},
		{"HMAC-SHA384", NewHMACSHA384, SumHMACSHA384},
		{"HMAC-SHA512", NewHMACSHA512, SumHMACSHA512},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := c.new(key)
			if _, err := h.Write(data); err != nil {
				t.Fatalf("Write: %v", err)
			}
			stream := h.Sum(nil)
			one := c.sum(key, data)
			if !bytes.Equal(stream, one) {
				t.Errorf("%s stream = %x, one-shot = %x", c.name, stream, one)
			}
		})
	}
}

// BenchmarkSumHMACSM3 测量 HMAC-SM3 一次性吞吐。
func BenchmarkSumHMACSM3(b *testing.B) {
	key := []byte("bench-key-of-decent-length")
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SumHMACSM3(key, data)
	}
}

// BenchmarkSumHMACSHA256 测量 HMAC-SHA256 一次性吞吐。
func BenchmarkSumHMACSHA256(b *testing.B) {
	key := []byte("bench-key-of-decent-length")
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SumHMACSHA256(key, data)
	}
}

// BenchmarkSumByName 测量按名分发的额外开销。
func BenchmarkSumByName(b *testing.B) {
	key := []byte("bench-key-of-decent-length")
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sum("HMAC-SM3", key, data, nil)
	}
}
