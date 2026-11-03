package asym_test

import (
	"encoding/hex"
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// ExampleFormatSignature 展示签名在 DER 与裸 r‖s 之间的互转。
// r 与 s 各取 32 字节（SM2 / P-256 的宽度）。
//
// ExampleFormatSignature shows signature conversion between DER and the
// bare r‖s form. Both r and s are 32 bytes wide (the SM2 / P-256 width).
func ExampleFormatSignature() {
	r := make([]byte, 32)
	s := make([]byte, 32)
	r[31] = 0x01
	s[31] = 0x02

	der, err := asym.SignatureDER(r, s)
	if err != nil {
		fmt.Println("encode:", err)
		return
	}
	fmt.Printf("der: %s (%d bytes)\n", hex.EncodeToString(der), len(der))

	raw, err := asym.FormatSignature(der, "der", "raw", 32)
	if err != nil {
		fmt.Println("convert:", err)
		return
	}
	fmt.Printf("raw: %d bytes, r padded: %v\n", len(raw), raw[0] == 0 && raw[31] == 0x01)
	// Output:
	// der: 3006020101020102 (8 bytes)
	// raw: 64 bytes, r padded: true
}
