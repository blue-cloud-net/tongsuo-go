package asym

import (
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"testing"
)

// TestRSAPSSDigestProbe 验证签验初始化探测、SM3 固定版本支持与错误参数。
//
// TestRSAPSSDigestProbe checks sign/verify initialization, fixed-version SM3 support and invalid arguments.
func TestRSAPSSDigestProbe(t *testing.T) {
	key, err := GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(key)
	for _, k := range []Key{key, key.Public()} {
		for _, hash := range []string{"sha256", "sm3"} {
			got, e := SupportsRSAPSSDigest(k, hash, PSSSaltLenDigest)
			if e != nil {
				t.Fatal(e)
			}
			want := hash == "sha256" || meta.VersionNum() >= 0x30500000
			if got != want {
				t.Fatalf("%s PSS=%v want %v", hash, got, want)
			}
		}
	}
	if _, e := SupportsRSAPSSDigest(key, "sha256", -4); e == nil {
		t.Fatal("invalid salt")
	}
	if _, e := SupportsRSAPSSDigest(nil, "sha256", PSSSaltLenDigest); e == nil {
		t.Fatal("nil key")
	}
	Close(key)
	if _, e := SupportsRSAPSSDigest(key, "sha256", PSSSaltLenDigest); e == nil {
		t.Fatal("closed key")
	}
}
