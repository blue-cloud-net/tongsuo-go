package sym

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestGCMSIVRFC8452 验证 RFC 8452 附录 C 的全部已提取标准向量与空消息认证。
//
// TestGCMSIVRFC8452 checks extracted RFC 8452 appendix C vectors and empty-message authentication.
func TestGCMSIVRFC8452(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc8452.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct{ Key, Nonce, Plaintext, AAD, Result string }
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 40 {
		t.Fatal("missing RFC vectors")
	}
	for i, v := range vectors.Cases {
		decode := func(s string) []byte {
			b, e := hex.DecodeString(s)
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		key, nonce, pt, aad, want := decode(v.Key), decode(v.Nonce), decode(v.Plaintext), decode(v.AAD), decode(v.Result)
		g, err := NewAESGCMSIV(key)
		if !Available("AES-128-GCM-SIV") {
			if meta.VersionNum() >= 0x30500000 {
				t.Fatal("8.5 baseline missing GCM-SIV")
			}
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unavailable: %v", err)
			}
			if _, _, err = EncryptAESGCMSIV(key, nonce, pt, aad); !errors.Is(err, ErrUnsupported) {
				t.Fatal(err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		got := g.Seal(nil, nonce, pt, aad)
		if !bytes.Equal(got, want) {
			t.Fatalf("vector %d: got %x want %x", i, got, want)
		}
		back, err := g.Open(nil, nonce, want, aad)
		if err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("vector %d: open %x %v", i, back, err)
		}
		ct, tag, err := EncryptAESGCMSIV(key, nonce, pt, aad)
		if err != nil || !bytes.Equal(append(ct, tag...), want) {
			t.Fatalf("vector %d: one shot %v", i, err)
		}
		for _, field := range []string{"tag", "nonce", "aad", "ciphertext"} {
			bad, iv, ad := append([]byte(nil), want...), append([]byte(nil), nonce...), append([]byte(nil), aad...)
			switch field {
			case "tag":
				bad[len(bad)-1] ^= 1
			case "nonce":
				iv[0] ^= 1
			case "aad":
				ad = append(ad, 1)
			case "ciphertext":
				if len(pt) == 0 {
					continue
				}
				bad[0] ^= 1
			}
			if out, e := g.Open(nil, iv, bad, ad); e == nil || out != nil {
				t.Fatalf("vector %d: %s tampering accepted", i, field)
			}
		}
	}
}

// TestGCMSIVBoundaries 验证所有密钥长度、分发入口、追加语义及非法参数。
//
// TestGCMSIVBoundaries checks all key lengths, dispatch, append semantics and invalid arguments.
func TestGCMSIVBoundaries(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		key, iv := make([]byte, size), make([]byte, 12)
		g, err := NewAESGCMSIV(key)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, pt := range [][]byte{nil, []byte("message"), bytes.Repeat([]byte{1}, 8193)} {
			out := g.Seal([]byte("pre"), iv, pt, []byte("aad"))
			if !bytes.HasPrefix(out, []byte("pre")) {
				t.Fatal("lost prefix")
			}
			back, e := g.Open([]byte("pre"), iv, out[3:], []byte("aad"))
			if e != nil || !bytes.Equal(back, append([]byte("pre"), pt...)) {
				t.Fatal(e)
			}
			ct, tag, e := EncryptAESGCMSIV(key, iv, pt, nil)
			if e != nil {
				t.Fatal(e)
			}
			if back, e = DecryptAESGCMSIV(key, iv, ct, tag, nil); e != nil || !bytes.Equal(back, pt) {
				t.Fatal(e)
			}
		}
		if _, _, e := EncryptAESGCMSIV(key, iv[:11], nil, nil); e == nil {
			t.Fatal("short nonce")
		}
		if _, e := DecryptAESGCMSIV(key, iv, nil, make([]byte, 15), nil); e == nil {
			t.Fatal("short tag")
		}
	}
	for _, size := range []int{0, 15, 17, 31, 33} {
		if _, e := NewAESGCMSIV(make([]byte, size)); !errors.Is(e, ErrInvalidKeyLength) {
			t.Fatal(e)
		}
	}
}

// FuzzGCMSIVRoundTrip 验证任意消息/AAD 的往返与篡改拒绝，旧版明确处理不可用。
//
// FuzzGCMSIVRoundTrip checks arbitrary message/AAD round trips and tamper rejection, handling unavailable builds explicitly.
func FuzzGCMSIVRoundTrip(f *testing.F) {
	f.Add([]byte("message"), []byte("header"))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, msg, aad []byte) {
		if len(msg) > 65536 || len(aad) > 65536 {
			return
		}
		g, err := NewAESGCMSIV(make([]byte, 16))
		if errors.Is(err, ErrUnsupported) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, 12)
		sealed := g.Seal(nil, nonce, msg, aad)
		plain, err := g.Open(nil, nonce, sealed, aad)
		if err != nil || !bytes.Equal(plain, msg) {
			t.Fatal("round trip", err)
		}
		sealed[len(sealed)-1] ^= 1
		if plain, err = g.Open(nil, nonce, sealed, aad); err == nil || plain != nil {
			t.Fatal("accepted tamper")
		}
	})
}

// BenchmarkAESGCMSIV 测量 4 KiB 消息的 AES-128-GCM-SIV 一次性加密。
//
// BenchmarkAESGCMSIV measures one-shot AES-128-GCM-SIV encryption of 4 KiB messages.
func BenchmarkAESGCMSIV(b *testing.B) {
	key, nonce, msg := make([]byte, 16), make([]byte, 12), make([]byte, 4096)
	if !Available("AES-128-GCM-SIV") {
		b.Skip("AES-GCM-SIV unavailable in this native build")
	}
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := EncryptAESGCMSIV(key, nonce, msg, nil); err != nil {
			b.Fatal(err)
		}
	}
}
