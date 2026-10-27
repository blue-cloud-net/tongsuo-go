package mac

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// mustHex 解码十六进制字符串，失败即终止测试。
//
// mustHex decodes a hexadecimal string and fails the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// TestCMACKnownVectors 验证 CMAC 对共享向量库的期望值。
//
// 向量来源（铜锁源码 test/recipes/30-test_evp_data/evpmac_common.txt）：
// AES-128-CBC / AES-192-CBC / AES-256-CBC 各一条。
//
// TestCMACKnownVectors verifies CMAC against the expected values of the
// shared vector corpus (Tongsuo's evpmac_common.txt): one vector each for
// AES-128-CBC / AES-192-CBC / AES-256-CBC.
func TestCMACKnownVectors(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
		key    string
		input  string
		want   string
	}{
		{
			name:   "AES-128-CBC",
			cipher: "AES-128",
			key:    "77A77FAF290C1FA30C683DF16BA7A77B",
			input:  "020683E1F0392F4CAC54318B6029259E9C553DBC4B6AD998E64D58E4E7DC2E13",
			want:   "FBFEA41BF9740CB501F1292C21CEBB40",
		},
		{
			name:   "AES-192-CBC",
			cipher: "AES-192",
			key:    "7B32391369AA4CA97558095BE3C3EC862BD057CEF1E32D62",
			input:  "",
			want:   "E4D9340B03E67DEFD4969CC1ED3735E6",
		},
		{
			name:   "AES-256-CBC",
			cipher: "AES-256",
			key:    "0B122AC8F34ED1FE082A3625D157561454167AC145A10BBF77C6A70596D574F1",
			input:  "498B53FDEC87EDCBF07097DCCDE93A084BAD7501A224E388DF349CE18959FE8485F8AD1537F0D896EA73BEDC7214713F",
			want:   "F62C46329B41085625669BAF51DEA66A",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CMAC(tt.cipher, mustHex(t, tt.key), mustHex(t, tt.input))
			if err != nil {
				t.Fatalf("CMAC: %v", err)
			}
			if !bytes.Equal(got, mustHex(t, tt.want)) {
				t.Fatalf("CMAC = %X, want %X", got, mustHex(t, tt.want))
			}
			// 完整名（带 "-CBC"）必须与短名等价。
			got2, err := Sum("CMAC", mustHex(t, tt.key), mustHex(t, tt.input),
				&Options{Cipher: tt.cipher + "-CBC"})
			if err != nil {
				t.Fatalf("Sum(CMAC, full name): %v", err)
			}
			if !bytes.Equal(got, got2) {
				t.Fatalf("full cipher name mismatch: %X != %X", got2, got)
			}
		})
	}
}

// TestGMACKnownVectors 验证 GMAC 对共享向量库的期望值。
//
// 向量来源：evpmac_common.txt 的 IEEE 802.1 测试向量。
//
// TestGMACKnownVectors verifies GMAC against the expected values of the
// shared vector corpus (the IEEE 802.1 vectors in evpmac_common.txt).
func TestGMACKnownVectors(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
		key    string
		iv     string
		input  string
		want   string
	}{
		{
			name:   "AES-128-GCM/1",
			cipher: "AES-128",
			key:    "77BE63708971C4E240D1CB79E8D77FEB",
			iv:     "E0E00F19FED7BA0136A797F3",
			input:  "7A43EC1D9C0A5A78A0B16533A6213CAB",
			want:   "209FCC8D3675ED938E9C7166709DD946",
		},
		{
			name:   "AES-128-GCM/2",
			cipher: "AES-128",
			key:    "AD7A2BD03EAC835A6F620FDCB506B345",
			iv:     "12153524C0895E81B2C28465",
			input:  "D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001",
			want:   "F09478A9B09007D06F46E9B6A1DA25DD",
		},
		{
			name:   "AES-256-GCM",
			cipher: "AES-256",
			key:    "E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72",
			iv:     "12153524C0895E81B2C28465",
			input:  "D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001",
			want:   "F09478A9B09007D06F46E9B6A1DA25DD",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := mustHex(t, tt.want)
			if tt.name == "AES-256-GCM" {
				// 该向量在 AES-256 下的期望值见下方断言（与 AES-128 不同）。
				want = mustHex(t, "2F0BC5AF409E06D609EA8B7D0FA5EA50")
			}
			got, err := GMAC(tt.cipher, mustHex(t, tt.key), mustHex(t, tt.iv), nil, mustHex(t, tt.input))
			if err != nil {
				t.Fatalf("GMAC: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("GMAC = %X, want %X", got, want)
			}
		})
	}
}

// TestGMACAADMatchesConcatenation 验证 AAD 与数据的拼接语义。
//
// provider 的 GMAC 把全部输入都当作 AAD，因此 GMAC(key, iv, aad, data)
// 必须等于 GMAC(key, iv, nil, aad||data)。
//
// TestGMACAADMatchesConcatenation verifies the AAD concatenation
// semantics: the provider's GMAC treats all input as AAD, so
// GMAC(key, iv, aad, data) must equal GMAC(key, iv, nil, aad||data).
func TestGMACAADMatchesConcatenation(t *testing.T) {
	key := bytes.Repeat([]byte{0x2b}, 16)
	iv := bytes.Repeat([]byte{0x01}, 12)
	aad := []byte("additional")
	data := []byte("payload")

	split, err := GMAC("AES-128", key, iv, aad, data)
	if err != nil {
		t.Fatalf("GMAC: %v", err)
	}
	joined, err := GMAC("AES-128", key, iv, nil, append(append([]byte(nil), aad...), data...))
	if err != nil {
		t.Fatalf("GMAC: %v", err)
	}
	if !bytes.Equal(split, joined) {
		t.Fatalf("AAD semantics mismatch: %X != %X", split, joined)
	}
}

// TestKMACKnownVectors 验证 KMAC-128 / KMAC-256 对 NIST SP 800-185 向量。
//
// 向量来源：evpmac_common.txt 的 KMAC 样例（NIST SP 800-185 附录）。
//
// TestKMACKnownVectors verifies KMAC-128 / KMAC-256 against the NIST
// SP 800-185 samples in evpmac_common.txt.
func TestKMACKnownVectors(t *testing.T) {
	key := mustHex(t, "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	input := mustHex(t, "00010203")

	t.Run("KMAC-128/no-custom", func(t *testing.T) {
		got, err := KMAC128(key, input, nil, 32)
		if err != nil {
			t.Fatalf("KMAC128: %v", err)
		}
		want := mustHex(t, "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E")
		if !bytes.Equal(got, want) {
			t.Fatalf("KMAC128 = %X, want %X", got, want)
		}
	})

	t.Run("KMAC-128/custom", func(t *testing.T) {
		got, err := KMAC128(key, input, []byte("My Tagged Application"), 32)
		if err != nil {
			t.Fatalf("KMAC128: %v", err)
		}
		want := mustHex(t, "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5")
		if !bytes.Equal(got, want) {
			t.Fatalf("KMAC128 = %X, want %X", got, want)
		}
	})

	t.Run("KMAC-256/custom", func(t *testing.T) {
		got, err := KMAC256(key, input, []byte("My Tagged Application"), 64)
		if err != nil {
			t.Fatalf("KMAC256: %v", err)
		}
		want := mustHex(t, "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"+
			"F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD")
		if !bytes.Equal(got, want) {
			t.Fatalf("KMAC256 = %X, want %X", got, want)
		}
	})
}

// TestSipHashKnownVectors 验证 SipHash 对共享向量库的期望值。
//
// 向量来源：evpmac_siphash.txt（默认 2/4 轮、16 字节输出）。
//
// TestSipHashKnownVectors verifies SipHash against the expected values of
// the shared vector corpus (evpmac_siphash.txt, default 2/4 rounds and
// 16-byte output).
func TestSipHashKnownVectors(t *testing.T) {
	key := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "a3817f04ba25a8e66df67214c7550293"},
		{"00", "00", "da87c1d86b99af44347659119b22fc45"},
		{"0001", "0001", "8177228da4a45dc7fca38bdef60affe4"},
		{"000102", "000102", "9c70b60c5267a94e5f33b6b02985ed51"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SipHash(key, mustHex(t, tt.input))
			if err != nil {
				t.Fatalf("SipHash: %v", err)
			}
			if !bytes.Equal(got, mustHex(t, tt.want)) {
				t.Fatalf("SipHash = %x, want %x", got, mustHex(t, tt.want))
			}
		})
	}

	// 输出长度可通过 Options.OutputLen 调整（8..16 字节）。
	// 注意：size 改变的是 SipHash 的输出变体（64 位 vs 128 位），
	// 而不是简单截断，故此处只断言长度，逐字节值由 CLI 对拍覆盖。
	short, err := Sum("SIPHASH", key, nil, &Options{OutputLen: 8})
	if err != nil {
		t.Fatalf("Sum(SIPHASH, size 8): %v", err)
	}
	if len(short) != 8 {
		t.Fatalf("SIPHASH size 8 => %d bytes, want 8", len(short))
	}
}

// TestPoly1305KnownVector 验证 Poly1305 对 RFC 8439 §2.5.2 的标准向量。
//
// TestPoly1305KnownVector verifies Poly1305 against the RFC 8439
// section 2.5.2 test vector.
func TestPoly1305KnownVector(t *testing.T) {
	key := mustHex(t, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	got, err := Poly1305(key, []byte("Cryptographic Forum Research Group"))
	if err != nil {
		t.Fatalf("Poly1305: %v", err)
	}
	want := mustHex(t, "a8061dc1305136c6c22b8baf0c0127a9")
	if !bytes.Equal(got, want) {
		t.Fatalf("Poly1305 = %x, want %x", got, want)
	}
}

// TestEIA3KnownVectors 验证 EIA3 对铜锁自带测试向量。
//
// 向量来源：evpmac_zuc_eia3.txt（前两条）。
//
// TestEIA3KnownVectors verifies EIA3 against the Tongsuo test vectors
// (the first two entries of evpmac_zuc_eia3.txt).
func TestEIA3KnownVectors(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		count string
		input string
		want  string
	}{
		{
			name:  "test1",
			key:   "00000000000000000000000000000000",
			count: "0000000000",
			input: "00",
			want:  "390a91b7",
		},
		{
			name:  "test2",
			key:   "47054125561eb2dda94059da05097850",
			count: "561eb2dda0",
			input: "000000000000000000000000",
			want:  "89a58b47",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EIA3(mustHex(t, tt.key), mustHex(t, tt.count), mustHex(t, tt.input))
			if err != nil {
				t.Fatalf("EIA3: %v", err)
			}
			if !bytes.Equal(got, mustHex(t, tt.want)) {
				t.Fatalf("EIA3 = %x, want %x", got, mustHex(t, tt.want))
			}
		})
	}
}

// TestFamiliesRequireMandatoryOptions 验证缺少必需参数时报 ErrInvalidOptions。
//
// TestFamiliesRequireMandatoryOptions verifies that a missing mandatory
// parameter reports ErrInvalidOptions.
func TestFamiliesRequireMandatoryOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
	}{
		{"CMAC", nil},
		{"GMAC", &Options{Cipher: "AES-128"}},
		{"EIA3", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Sum(tt.name, bytes.Repeat([]byte{1}, 16), []byte("x"), tt.opts)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("Sum(%q) err = %v, want ErrInvalidOptions", tt.name, err)
			}
		})
	}
}

// TestUnknownCipherRejected 验证未知底层分组算法名被拒绝。
//
// TestUnknownCipherRejected verifies that an unknown underlying block
// cipher name is rejected instead of silently succeeding.
func TestUnknownCipherRejected(t *testing.T) {
	_, err := CMAC("NO-SUCH-CIPHER", bytes.Repeat([]byte{1}, 16), []byte("x"))
	if err == nil {
		t.Fatal("CMAC: expected error for unknown cipher")
	}
	if !strings.Contains(err.Error(), "CMAC") {
		t.Errorf("error %v should mention the algorithm", err)
	}
}
