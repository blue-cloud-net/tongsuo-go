package kdf_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/kdf"
)

// requireHex 解码十六进制测试向量（先剥掉换行与空白）。
//
// requireHex decodes a hex test vector after stripping whitespace.
func requireHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
		default:
			clean = append(clean, s[i])
		}
	}
	b, err := hex.DecodeString(string(clean))
	if err != nil {
		t.Fatalf("decode hex vector: %v", err)
	}
	return b
}

// TestScryptVector 验证 scrypt 派生与 draft-josefsson-id-scrypt-kdf-03 向量一致。
// 向量来源：evpkdf_scrypt.txt 第 1/2 条。
//
// TestScryptVector verifies scrypt derivation against the
// draft-josefsson-id-scrypt-kdf-03 vectors (evpkdf_scrypt.txt items 1/2).
func TestScryptVector(t *testing.T) {
	// 向量来源：evpkdf_scrypt.txt 第 2 条（password / NaCl）。
	// 第 1 条向量的口令与盐均为空串，本库的公开入口拒绝空口令，故不收录。
	//
	// Source: the second vector in evpkdf_scrypt.txt (password / NaCl).
	// The first vector uses an empty password and salt, which the public
	// entry rejects, so it is not covered here.
	password := []byte("password")
	salt := []byte("NaCl")
	want := requireHex(t, "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"+
		"2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640")

	got, err := kdf.Scrypt(password, salt, 1024, 8, 16, 0, 64)
	if err != nil {
		t.Fatalf("scrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("scrypt output mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestSSKDFVector 验证单步 KDF 与 evpkdf_ss.txt 向量一致。
//
// TestSSKDFVector verifies the single-step KDF against evpkdf_ss.txt.
func TestSSKDFVector(t *testing.T) {
	secret := requireHex(t, "d09a6b1a472f930db4f5e6b967900744")
	info := requireHex(t, "b117255ab5f1b6b96fc434b0")
	want := requireHex(t, "b5a3c52e97ae6e8c5069954354eab3c7")

	got, err := kdf.SSKDF(kdf.HashSHA1, secret, nil, info, 16)
	if err != nil {
		t.Fatalf("SSKDF: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("SSKDF = %x, want %x", got, want)
	}
}

// TestTLS1PRFVector 验证 TLS 1.0/1.1 PRF 与 evpkdf_tls11_prf.txt 的
// master secret 向量一致。
//
// TestTLS1PRFVector verifies TLS 1.0/1.1 PRF against the master-secret
// vector in evpkdf_tls11_prf.txt.
func TestTLS1PRFVector(t *testing.T) {
	secret := requireHex(t, "bded7fa5c1699c010be23dd06ada3a48349f21e5f86263d512c0c5cc"+
		"379f0e780ec55d9844b2f1db02a96453513568d0")
	clientRandom := requireHex(t, "e5acaf549cd25c22d964c0d930fa4b5261d2507fad84c33715b"+
		"7b9a864020693")
	serverRandom := requireHex(t, "135e4d557fdf3aa6406d82975d5c606a9734c9334b42136e969"+
		"90fbd5358cdb2")

	seed := append([]byte("master secret"), clientRandom...)
	seed = append(seed, serverRandom...)

	want := requireHex(t, "2f6962dfbc744c4b2138bb6b3d33054c5ecc14f24851d9896395a44ab3964efc"+
		"2090c5bf51a0891209f46c1e1e998f62")

	got, err := kdf.TLS1PRF(kdf.HashMD5SHA1, secret, seed, 48)
	if err != nil {
		t.Fatalf("TLS1PRF: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("TLS1PRF = %x, want %x", got, want)
	}
}

// TestTLS13KDFVector 验证 TLS 1.3 KDF 的 Extract / Expand 两步与
// evpkdf_tls13_kdf.txt 前两条向量一致。
//
// TestTLS13KDFVector verifies the TLS 1.3 KDF extract and expand steps
// against the first two vectors in evpkdf_tls13_kdf.txt.
func TestTLS13KDFVector(t *testing.T) {
	ikm := requireHex(t, "f8af6aea2d397baf2948a25b2834200692cff17eee9165e4e27babee9edefd05")
	wantExtract := requireHex(t, "153b6394a9c03cf3f5accc6e455a7693281138a1bcfa3803c26735dd1194d216")

	got, err := kdf.TLS13KDFExtract(kdf.HashSHA256, ikm, nil)
	if err != nil {
		t.Fatalf("TLS13KDFExtract: %v", err)
	}
	if !bytes.Equal(got, wantExtract) {
		t.Fatalf("extract = %x, want %x", got, wantExtract)
	}

	// 第二条向量：EXPAND_ONLY，key 为上一步输出，data 为 transcript 摘要，
	// prefix 为 "tls13 "，label 为 "c e traffic"。
	data := requireHex(t, "7c92f68bd5bf3638ea338a6494722e1b44127e1b7e8aad535f2322a644ff22b3")
	label := requireHex(t, "6320652074726166666963")
	prefix := requireHex(t, "746c73313320")
	if string(prefix) != "tls13 " {
		t.Fatalf("vector prefix = %q, want \"tls13 \"", prefix)
	}
	wantExpand := requireHex(t, "c80583a90e995c489600492a5da642e6b1f679ba674828792df087b939636171")

	expand, err := kdf.Derive("TLS13-KDF", &kdf.Options{
		Digest: kdf.HashSHA256,
		Mode:   "EXPAND_ONLY",
		Secret: got,
		Label:  label,
		Prefix: prefix,
		Data:   data,
		Length: 32,
	})
	if err != nil {
		t.Fatalf("TLS13-KDF expand: %v", err)
	}
	if !bytes.Equal(expand, wantExpand) {
		t.Errorf("expand = %x, want %x", expand, wantExpand)
	}

	// TLS13KDFExpand 的便捷入口应产生相同结果。
	helper, err := kdf.TLS13KDFExpand(kdf.HashSHA256, got, string(label), data, 32)
	if err != nil {
		t.Fatalf("TLS13KDFExpand: %v", err)
	}
	if !bytes.Equal(helper, wantExpand) {
		t.Errorf("TLS13KDFExpand = %x, want %x", helper, wantExpand)
	}
}

// TestX963KDFVector 验证 ANSI X9.63 KDF 与 evpkdf_x963.txt 首条向量一致。
//
// TestX963KDFVector verifies the ANSI X9.63 KDF against the first vector
// in evpkdf_x963.txt.
func TestX963KDFVector(t *testing.T) {
	secret := requireHex(t, "fd17198b89ab39c4ab5d7cca363b82f9fd7e23c3984dc8a2")
	info := requireHex(t, "856a53f3e36a26bbc5792879f307cce2")
	want := requireHex(t, "6e5fad865cb4a51c95209b16df0cc490bc2c9064405c5bccd4ee4832a531fbe7"+
		"f10cb79e2eab6ab1149fbd5a23cfdabc41242269c9df22f628c4424333855b64e9"+
		"5e2d4fb8469c669f17176c07d103376b10b384ec5763d8b8c610409f19aca8eb31"+
		"f9d85cc61a8d6d4a03d03e5a506b78d6847e93d295ee548c65afedd2efec")

	got, err := kdf.X963KDF(kdf.HashSHA1, secret, info, len(want))
	if err != nil {
		t.Fatalf("X963KDF: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("X963KDF = %x, want %x", got, want)
	}
}

// TestX942KDFVector 验证 ANSI X9.42 KDF 与 evpkdf_x942.txt 首条向量一致。
//
// TestX942KDFVector verifies the ANSI X9.42 KDF against the first vector
// in evpkdf_x942.txt.
func TestX942KDFVector(t *testing.T) {
	secret := requireHex(t, "000102030405060708090a0b0c0d0e0f10111213")
	want := requireHex(t, "d6d6b094c1027a7de6e3117294a35364")

	got, err := kdf.X942KDF(kdf.HashSHA1, secret, nil, "id-aes128-wrap", false, 16)
	if err != nil {
		t.Fatalf("X942KDF: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("X942KDF = %x, want %x", got, want)
	}
}

// TestKBKDFVector 验证 SP 800-108 KBKDF（HMAC 计数器模式）与
// evpkdf_kbkdf_counter.txt 的 COUNT=0 向量一致。
//
// TestKBKDFVector verifies the SP 800-108 KBKDF (HMAC counter mode)
// against the COUNT=0 vector in evpkdf_kbkdf_counter.txt.
func TestKBKDFVector(t *testing.T) {
	key := requireHex(t, "00a39bd547fb88b2d98727cf64c195c61e1cad6c")
	info := requireHex(t, "98132c1ffaf59ae5cbc0a3133d84c551bb97e0c75ecaddfc30056f6876f59803"+
		"009bffc7d75c4ed46f40b8f80426750d15bc1ddb14ac5dcb69a68242")
	want := requireHex(t, "0611e1903609b47ad7a5fc2c82e47702")

	got, err := kdf.KBKDF(&kdf.KBKDFOptions{
		Digest:  kdf.HashSHA1,
		MAC:     "HMAC",
		Mode:    "COUNTER",
		Secret:  key,
		Context: info,
		R:       8,
	}, 16)
	if err != nil {
		t.Fatalf("KBKDF(HMAC): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("KBKDF(HMAC) = %x, want %x", got, want)
	}
}

// TestHMACDRBGVector 验证 HMAC-DRBG KDF 与 evpkdf_hmac_drbg.txt 首条向量一致。
//
// TestHMACDRBGVector verifies the HMAC-DRBG KDF against the first vector
// in evpkdf_hmac_drbg.txt.
func TestHMACDRBGVector(t *testing.T) {
	entropy := requireHex(t, "411602cb19a6ccc34494d79d98ef1e7ed5af25f7")
	nonce := requireHex(t, "8151325dcdbae9e0ff95f9f9658432dbedfdb209")
	want := requireHex(t, "7bdb6b0ff756e1bb5d53583ef979082f9ad5bd5b")

	got, err := kdf.HMACDRBG(kdf.HashSHA1, entropy, nonce, len(want))
	if err != nil {
		t.Fatalf("HMACDRBG: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("HMACDRBG = %x, want %x", got, want)
	}
}

// TestDeriveDeterministic 验证同一输入多次派生结果一致（无隐藏状态）。
//
// TestDeriveDeterministic verifies that repeated derivations with the
// same inputs agree (no hidden state).
func TestDeriveDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, 32)
	first, err := kdf.X963KDF(kdf.HashSM3, secret, []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("X963KDF: %v", err)
	}
	second, err := kdf.X963KDF(kdf.HashSM3, secret, []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("X963KDF again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("X963KDF not deterministic: %x vs %x", first, second)
	}
	if bytes.Equal(first, secret[:len(first)]) {
		t.Fatalf("X963KDF returned the input secret unchanged")
	}
}

// TestDeriveValidation 验证各算法必填字段缺失时返回明确错误。
//
// TestDeriveValidation verifies that missing required fields produce
// explicit errors for every algorithm.
func TestDeriveValidation(t *testing.T) {
	cases := []struct {
		name string
		opts *kdf.Options
	}{
		{"SCRYPT/empty-salt", &kdf.Options{Password: []byte("p"), Length: 16}},
		{"SCRYPT/bad-cost", &kdf.Options{Password: []byte("p"), Salt: []byte("s"), Length: 16}},
		{"SSKDF/empty-secret", &kdf.Options{Digest: kdf.HashSHA256, Length: 16}},
		{"TLS1-PRF/no-seed", &kdf.Options{Digest: kdf.HashMD5SHA1, Secret: []byte("s"), Length: 16}},
		{"TLS13-KDF/no-mode", &kdf.Options{Digest: kdf.HashSHA256, Secret: []byte("s"), Length: 16}},
		{"TLS13-KDF/bad-mode", &kdf.Options{Digest: kdf.HashSHA256, Mode: "AUTO", Secret: []byte("s"), Length: 16}},
		{"KBKDF/no-mac", &kdf.Options{Digest: kdf.HashSHA256, Secret: []byte("s"), Length: 16}},
		{"KBKDF/bad-mode", &kdf.Options{Digest: kdf.HashSHA256, Mode: "XOR", MAC: "HMAC", Secret: []byte("s"), Length: 16}},
		{"X942KDF/no-cekalg", &kdf.Options{Digest: kdf.HashSHA1, Secret: []byte("s"), Length: 16}},
		{"X963KDF/empty-secret", &kdf.Options{Digest: kdf.HashSHA1, Length: 16}},
		{"HMAC-DRBG-KDF/no-entropy", &kdf.Options{Digest: kdf.HashSHA1, Length: 16}},
		{"HKDF/zero-length", &kdf.Options{Digest: kdf.HashSHA1, Secret: []byte("s")}}}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			name := tc.name
			if i := indexByte(name, '/'); i > 0 {
				name = name[:i]
			}
			_, err := kdf.Derive(name, tc.opts)
			if err == nil {
				t.Fatalf("Derive(%q) with %s: want error, got nil", name, tc.name)
			}
		})
	}
}

// TestKBKDFNilOptions 验证 KBKDF 拒绝 nil 参数包。
//
// TestKBKDFNilOptions verifies that KBKDF rejects a nil option struct.
func TestKBKDFNilOptions(t *testing.T) {
	if _, err := kdf.KBKDF(nil, 16); err == nil {
		t.Fatal("KBKDF(nil): want error, got nil")
	}
}

// TestKBKDFTypedMatchesDerive 验证 KBKDF 便捷入口与 Derive 等价。
//
// TestKBKDFTypedMatchesDerive verifies that the KBKDF convenience entry
// matches Derive.
func TestKBKDFTypedMatchesDerive(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5c}, 16)
	ctx := []byte("context")
	viaTyped, err := kdf.KBKDF(&kdf.KBKDFOptions{
		Digest:  kdf.HashSHA256,
		MAC:     "HMAC",
		Secret:  secret,
		Label:   []byte("label"),
		Context: ctx,
	}, 32)
	if err != nil {
		t.Fatalf("KBKDF typed: %v", err)
	}
	viaDerive, err := kdf.Derive("KBKDF", &kdf.Options{
		Digest: kdf.HashSHA256,
		Mode:   "COUNTER",
		MAC:    "HMAC",
		Secret: secret,
		Salt:   []byte("label"),
		Info:   ctx,
		R:      32,
		Length: 32,
	})
	if err != nil {
		t.Fatalf("KBKDF derive: %v", err)
	}
	if !bytes.Equal(viaTyped, viaDerive) {
		t.Fatalf("typed = %x, derive = %x", viaTyped, viaDerive)
	}
}

// TestX942KDFUnknownCEKAlg 验证未知 CEK 算法名返回包装错误而非 panic。
//
// TestX942KDFUnknownCEKAlg verifies that an unknown CEK algorithm name
// returns a wrapped error instead of panicking.
func TestX942KDFUnknownCEKAlg(t *testing.T) {
	_, err := kdf.X942KDF(kdf.HashSHA1, bytes.Repeat([]byte{1}, 16), nil, "no-such-cek", false, 16)
	if err == nil {
		t.Fatal("X942KDF with unknown cekAlg: want error, got nil")
	}
	if errors.Is(err, kdf.ErrUnknownAlgorithm) || errors.Is(err, kdf.ErrUnsupported) {
		t.Fatalf("unexpected sentinel for cekAlg failure: %v", err)
	}
}

// indexByte 是 strings.IndexByte 的本地副本，避免为单个调用引入额外导入。
//
// indexByte is a local copy of strings.IndexByte so this file needs no
// extra import for a single call.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
