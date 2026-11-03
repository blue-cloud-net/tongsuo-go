//go:build tongsuocli

package sym

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"testing"
)

// TestCLIExtendedModes 验证 WRAP、CBC-CTS 与 ZUC 逐字节对拍。
//
// TestCLIExtendedModes checks WRAP, CBC-CTS and ZUC byte-for-byte against the CLI.
func TestCLIExtendedModes(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	names := []string{"ZUC-128-EEA3"}
	for _, bits := range []int{128, 192, 256} {
		for _, mode := range []string{"WRAP", "WRAP-PAD", "CBC-CTS"} {
			names = append(names, fmt.Sprintf("AES-%d-%s", bits, mode))
		}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			a, _, err := lookup(name)
			if err != nil {
				t.Fatal(err)
			}
			key := make([]byte, a.size)
			for i := range key {
				key[i] = byte(i)
			}
			iv := make([]byte, 16)
			pt := bytes.Repeat([]byte{0x31}, 31)
			switch a.mode {
			case "WRAP":
				iv = bytes.Repeat([]byte{0xa6}, 8)
				pt = pt[:24]
			case "WRAP-PAD":
				iv = []byte{0xa6, 0x59, 0x59, 0xa6}
			case "STREAM":
				iv = make([]byte, 5)
			}
			ct, err := Encrypt(name, key, iv, pt, nil)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"enc", "-" + name, "-K", hex.EncodeToString(key), "-iv", hex.EncodeToString(iv), "-nosalt", "-nopad"}
			out, err := testutil.RunOpenSSL(args, pt)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, ct) {
				t.Fatalf("CLI=%x library=%x", out, ct)
			}
			out, err = testutil.RunOpenSSL(append(args, "-d"), ct)
			if err != nil || !bytes.Equal(out, pt) {
				t.Fatalf("CLI decrypt: %x %v", out, err)
			}
		})
	}
}
