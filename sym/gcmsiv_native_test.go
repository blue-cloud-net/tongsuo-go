package sym

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os/exec"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
)

// TestGCMSIVNativeInterop 使用独立 EVP 驱动双向对拍三个密钥长度及空消息。
//
// TestGCMSIVNativeInterop compares all key lengths and empty messages with an independent EVP driver.
func TestGCMSIVNativeInterop(t *testing.T) {
	if !Available("AES-128-GCM-SIV") {
		return // Unsupported behavior is asserted by TestGCMSIVRFC8452.
	}
	driver, err := testutil.BuildNative(t.TempDir(), "testdata/evp.c")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{16, 24, 32} {
		key, nonce, aad := make([]byte, size), make([]byte, 12), []byte("AAD")
		for _, pt := range [][]byte{nil, []byte("independent native round trip")} {
			ct, tag, err := EncryptAESGCMSIV(key, nonce, pt, aad)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{fmt.Sprintf("AES-%d-GCM-SIV", size*8), hex.EncodeToString(key), hex.EncodeToString(nonce), hex.EncodeToString(aad), "", "enc"}
			cmd := exec.Command(driver, args...)
			cmd.Stdin = bytes.NewReader(pt)
			out, err := cmd.Output()
			if err != nil || !bytes.Equal(out, append(ct, tag...)) {
				t.Fatalf("EVP encrypt %x %v", out, err)
			}
			args[4], args[5] = hex.EncodeToString(tag), "dec"
			cmd = exec.Command(driver, args...)
			cmd.Stdin = bytes.NewReader(ct)
			out, err = cmd.Output()
			if err != nil || !bytes.Equal(out, pt) {
				t.Fatalf("EVP decrypt %x %v", out, err)
			}
		}
	}
}
