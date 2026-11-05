package sym

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// TestSIVEmptyAuthentication 验证空消息与独立 EVP 一致，且错误 tag/AAD/密钥均被拒绝。
//
// TestSIVEmptyAuthentication checks empty messages against independent EVP and rejects wrong tags, AAD and keys.
func TestSIVEmptyAuthentication(t *testing.T) {
	if meta.VersionNum() < 0x30500000 {
		if _, _, err := EncryptAESSIV(make([]byte, 32), nil, nil, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
		return
	}
	driver, err := testutil.BuildNative(t.TempDir(), "testdata/evp.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{32, 48, 64} {
		key := make([]byte, size)
		for _, aad := range [][]byte{nil, []byte("AAD")} {
			ct, tag, err := EncryptAESSIV(key, nil, nil, aad)
			if err != nil || len(ct) != 0 || len(tag) != 16 {
				t.Fatal(err)
			}
			args := []string{fmt.Sprintf("AES-%d-SIV", size*4), hex.EncodeToString(key), "", hex.EncodeToString(aad), "", "enc"}
			cmd := exec.Command(driver, args...)
			cmd.Stdin = bytes.NewReader(nil)
			out, err := cmd.Output()
			if err != nil || !bytes.Equal(out, tag) {
				t.Fatalf("native SIV empty %x != %x: %v", out, tag, err)
			}
			plain, err := DecryptAESSIV(key, nil, ct, tag, aad)
			if err != nil || len(plain) != 0 {
				t.Fatal(err)
			}
			for _, field := range []string{"tag", "aad", "key"} {
				k, ad, tg := append([]byte(nil), key...), append([]byte(nil), aad...), append([]byte(nil), tag...)
				switch field {
				case "tag":
					tg[0] ^= 1
				case "aad":
					ad = append(ad, 1)
				case "key":
					k[0] ^= 1
				}
				if out, e := DecryptAESSIV(k, nil, nil, tg, ad); e == nil || out != nil {
					t.Fatalf("accepted empty SIV %s tamper", field)
				}
			}
		}
	}
}
