package mac_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/mac"
)

// ExampleCMAC 演示用 SM4 计算 CMAC 标签。
//
// ExampleCMAC demonstrates computing a CMAC tag with SM4.
func ExampleCMAC() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tag, err := mac.CMAC("SM4", key, []byte("tongsuo-go"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(tag))
	// Output: 16
}

// ExampleGMAC 演示用 AES-128-GCM 计算 GMAC 标签。
//
// ExampleGMAC demonstrates computing a GMAC tag with AES-128-GCM.
func ExampleGMAC() {
	key := []byte("0123456789abcdef")
	nonce, _ := hex.DecodeString("e0e00f19fed7ba0136a797f3")
	aad := []byte("header")
	tag, err := mac.GMAC("AES-128", key, nonce, nil, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(tag))
	// Output: 16
}

// ExampleKMAC256 演示按 NIST SP 800-185 计算 KMAC-256 标签。
//
// ExampleKMAC256 demonstrates computing a KMAC-256 tag per NIST SP 800-185.
func ExampleKMAC256() {
	key, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	data, _ := hex.DecodeString("00010203")
	tag, err := mac.KMAC256(key, data, []byte("My Tagged Application"), 64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.ToUpper(hex.EncodeToString(tag)))
	// Output: 20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD
}

// ExampleSipHash 演示用 16 字节密钥计算 SipHash 标签。
//
// ExampleSipHash demonstrates computing a SipHash tag with a 16-byte key.
func ExampleSipHash() {
	key, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	tag, err := mac.SipHash(key, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.ToLower(hex.EncodeToString(tag)))
	// Output: a3817f04ba25a8e66df67214c7550293
}

// ExamplePoly1305 演示按 RFC 8439 计算 Poly1305 标签。
//
// ExamplePoly1305 demonstrates computing a Poly1305 tag per RFC 8439.
func ExamplePoly1305() {
	key, _ := hex.DecodeString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	tag, err := mac.Poly1305(key, []byte("Cryptographic Forum Research Group"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.ToLower(hex.EncodeToString(tag)))
	// Output: a8061dc1305136c6c22b8baf0c0127a9
}

// ExampleEIA3 演示计算铜锁独有的 EIA3 标签。
//
// ExampleEIA3 demonstrates computing the Tongsuo-specific EIA3 tag.
func ExampleEIA3() {
	key := make([]byte, 16)
	count := make([]byte, 5)
	tag, err := mac.EIA3(key, count, []byte{0x00})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.ToLower(hex.EncodeToString(tag)))
	// Output: 390a91b7
}
