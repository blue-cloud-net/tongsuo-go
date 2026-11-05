//go:build tongsuocli

package sym

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"os/exec"
	"testing"
)

// TestCLIExtendedModes 验证 WRAP、CBC-CTS 与 ZUC 逐字节对拍。
//
// TestCLIExtendedModes checks WRAP, CBC-CTS and ZUC byte-for-byte against the CLI.
func TestCLIExtendedModes(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	driver, err := testutil.BuildNative(t.TempDir(), "testdata/evp.c")
	if err != nil {
		t.Fatal(err)
	}
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
			if meta.VersionNum() >= 0x30500000 && (a.mode == "WRAP" || a.mode == "WRAP-PAD") {
				out, e := testutil.RunOpenSSLCombined(args, pt)
				if e == nil || !bytes.Contains(out, []byte("Unstreamable cipher mode")) {
					t.Fatalf("unexpected CLI WRAP behavior: %s %v", out, e)
				}
				argv := []string{name, hex.EncodeToString(key), hex.EncodeToString(iv), "", "", "enc"}
				cmd := exec.Command(driver, argv...)
				cmd.Stdin = bytes.NewReader(pt)
				native, e := cmd.Output()
				if e != nil || !bytes.Equal(native, ct) {
					t.Fatalf("native WRAP: %x %v", native, e)
				}
				argv[5] = "dec"
				cmd = exec.Command(driver, argv...)
				cmd.Stdin = bytes.NewReader(ct)
				native, e = cmd.Output()
				if e != nil || !bytes.Equal(native, pt) {
					t.Fatalf("native unwrap: %x %v", native, e)
				}
				return
			}
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
