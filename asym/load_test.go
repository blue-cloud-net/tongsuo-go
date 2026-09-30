package asym

import (
	"bytes"
	"testing"
)

// TestLoadPrivateKeyPEMDispatch 验证算法无关加载器按底层算法分发到正确类型。
func TestLoadPrivateKeyPEMDispatch(t *testing.T) {
	cases := []struct {
		name    string
		gen     func(t *testing.T) PrivateKey
		wantAlg Algorithm
		isType  func(PrivateKey) bool
	}{
		{
			name: "SM2",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateSM2()
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgSM2,
			isType:  func(k PrivateKey) bool { _, ok := k.(*sm2PrivateKey); return ok },
		},
		{
			name: "RSA",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateRSA(2048)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgRSA,
			isType:  func(k PrivateKey) bool { _, ok := k.(*rsaPrivateKey); return ok },
		},
		{
			name: "EC",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateEC(CurveP256)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgEC,
			isType:  func(k PrivateKey) bool { _, ok := k.(*ecPrivateKey); return ok },
		},
		{
			name: "Ed25519",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateEd25519()
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgEd25519,
			isType:  func(k PrivateKey) bool { _, ok := k.(*ed25519PrivateKey); return ok },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			priv := c.gen(t)
			pem, err := priv.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadPrivateKeyPEM(pem)
			if err != nil {
				t.Fatalf("LoadPrivateKeyPEM: %v", err)
			}
			if loaded.Algorithm() != c.wantAlg {
				t.Errorf("alg = %s, want %s", loaded.Algorithm(), c.wantAlg)
			}
			if !c.isType(loaded) {
				t.Errorf("加载后未分发到 %s 对应的具体类型", c.wantAlg)
			}
			// 重新导出应与原 PEM 一致
			again, err := loaded.MarshalPrivateKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, pem) {
				t.Error("PEM 往返不一致")
			}
		})
	}
}

// TestLoadPublicKeyPEMDispatch 验证算法无关公钥加载器按算法分发。
func TestLoadPublicKeyPEMDispatch(t *testing.T) {
	cases := []struct {
		name    string
		gen     func(t *testing.T) PrivateKey
		wantAlg Algorithm
		isType  func(PublicKey) bool
	}{
		{
			name: "SM2",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateSM2()
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgSM2,
			isType:  func(k PublicKey) bool { _, ok := k.(*sm2PublicKey); return ok },
		},
		{
			name: "RSA",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateRSA(2048)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgRSA,
			isType:  func(k PublicKey) bool { _, ok := k.(*rsaPublicKey); return ok },
		},
		{
			name: "EC",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateEC(CurveP384)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgEC,
			isType:  func(k PublicKey) bool { _, ok := k.(*ecPublicKey); return ok },
		},
		{
			name: "Ed25519",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateEd25519()
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgEd25519,
			isType:  func(k PublicKey) bool { _, ok := k.(*ed25519PublicKey); return ok },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub := c.gen(t).Public()
			pem, err := pub.MarshalPublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadPublicKeyPEM(pem)
			if err != nil {
				t.Fatalf("LoadPublicKeyPEM: %v", err)
			}
			if loaded.Algorithm() != c.wantAlg {
				t.Errorf("alg = %s, want %s", loaded.Algorithm(), c.wantAlg)
			}
			if !c.isType(loaded) {
				t.Errorf("加载后未分发到 %s 对应的具体类型", c.wantAlg)
			}
		})
	}
}

// TestLoadEncryptedPrivateKeyPEMDispatch 验证加密 PEM 加载器的算法分发与口令校验。
func TestLoadEncryptedPrivateKeyPEMDispatch(t *testing.T) {
	cases := []struct {
		name    string
		gen     func(t *testing.T) PrivateKey
		wantAlg Algorithm
	}{
		{
			name: "SM2",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateSM2()
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgSM2,
		},
		{
			name: "RSA",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateRSA(2048)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgRSA,
		},
		{
			name: "EC",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateEC(CurveP256)
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgEC,
		},
		{
			name: "Ed25519",
			gen: func(t *testing.T) PrivateKey {
				k, err := GenerateEd25519()
				if err != nil {
					t.Fatal(err)
				}
				return k
			},
			wantAlg: AlgEd25519,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			priv := c.gen(t)
			enc, err := MarshalEncryptedPrivateKeyPEM(priv, "pw-"+c.name)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(enc, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
				t.Fatalf("加密 PEM 头异常：%q", enc[:32])
			}
			loaded, err := LoadEncryptedPrivateKeyPEM(enc, "pw-"+c.name)
			if err != nil {
				t.Fatalf("LoadEncryptedPrivateKeyPEM: %v", err)
			}
			if loaded.Algorithm() != c.wantAlg {
				t.Errorf("alg = %s, want %s", loaded.Algorithm(), c.wantAlg)
			}
			if _, err := LoadEncryptedPrivateKeyPEM(enc, "wrong"); err == nil {
				t.Error("错误口令应报错")
			}
		})
	}
}

// TestMarshalEncryptedPrivateKeyPEMWithCipher 验证指定 cipher 的加密导出。
func TestMarshalEncryptedPrivateKeyPEMWithCipher(t *testing.T) {
	for _, alg := range []Algorithm{AlgSM2, AlgEC, AlgEd25519} {
		t.Run(string(alg), func(t *testing.T) {
			var (
				priv PrivateKey
				err  error
			)
			switch alg {
			case AlgSM2:
				priv, err = GenerateSM2()
			case AlgEC:
				priv, err = GenerateEC(CurveP256)
			case AlgEd25519:
				priv, err = GenerateEd25519()
			}
			if err != nil {
				t.Fatal(err)
			}
			enc, err := MarshalEncryptedPrivateKeyPEMWithCipher(priv, "aes-128-cbc", "pw")
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadEncryptedPrivateKeyPEM(enc, "pw")
			if err != nil {
				t.Fatalf("aes-128-cbc 加密 PEM 加载失败：%v", err)
			}
			if loaded.Algorithm() != alg {
				t.Errorf("alg = %s, want %s", loaded.Algorithm(), alg)
			}
		})
	}
}

// TestChangePasswordAlgorithmAgnostic 验证改密入口与算法无关。
func TestChangePasswordAlgorithmAgnostic(t *testing.T) {
	for _, alg := range []Algorithm{AlgSM2, AlgEC, AlgEd25519} {
		t.Run(string(alg), func(t *testing.T) {
			var (
				priv PrivateKey
				err  error
			)
			switch alg {
			case AlgSM2:
				priv, err = GenerateSM2()
			case AlgEC:
				priv, err = GenerateEC(CurveP256)
			case AlgEd25519:
				priv, err = GenerateEd25519()
			}
			if err != nil {
				t.Fatal(err)
			}
			enc, err := MarshalEncryptedPrivateKeyPEM(priv, "old")
			if err != nil {
				t.Fatal(err)
			}
			re, err := ChangePassword(enc, "old", "new")
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadEncryptedPrivateKeyPEM(re, "new")
			if err != nil {
				t.Fatalf("改密后加载失败：%v", err)
			}
			if loaded.Algorithm() != alg {
				t.Errorf("alg = %s, want %s", loaded.Algorithm(), alg)
			}
			if _, err := LoadEncryptedPrivateKeyPEM(re, "old"); err == nil {
				t.Error("旧口令应已失效")
			}
		})
	}
}

// TestWrapKeyNilGuard 验证包装函数的 nil 守卫。
func TestWrapKeyNilGuard(t *testing.T) {
	if _, err := wrapPrivateKey(nil); err == nil {
		t.Error("wrapPrivateKey(nil) 应报错")
	}
	if _, err := wrapPublicKey(nil); err == nil {
		t.Error("wrapPublicKey(nil) 应报错")
	}
	if _, err := LoadPrivateKeyPEM(nil); err == nil {
		t.Error("LoadPrivateKeyPEM(nil) 应报错")
	}
	if _, err := LoadPublicKeyPEM(nil); err == nil {
		t.Error("LoadPublicKeyPEM(nil) 应报错")
	}
}
