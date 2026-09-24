package asym

import "testing"

// TestParamsAlgorithmAgnostic 验证 Params 对四种算法都返回正确的 Type 与关键分量。
func TestParamsAlgorithmAgnostic(t *testing.T) {
	t.Run("SM2", func(t *testing.T) {
		priv, err := GenerateSM2()
		if err != nil {
			t.Fatal(err)
		}
		p, err := Params(priv)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type != string(AlgSM2) {
			t.Errorf("Type = %q, want SM2", p.Type)
		}
		if p.Curve == "" || p.X == nil || p.Y == nil || p.D == nil {
			t.Errorf("SM2 参数不完整：Curve=%q X=%v Y=%v D=%v", p.Curve, p.X, p.Y, p.D)
		}
	})

	t.Run("RSA", func(t *testing.T) {
		priv, err := GenerateRSA(2048)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Params(priv)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type != string(AlgRSA) {
			t.Errorf("Type = %q, want RSA", p.Type)
		}
		for name, v := range map[string]interface{}{
			"N": p.N, "E": p.E, "D": p.D, "P": p.P, "Q": p.Q,
			"Dmp1": p.Dmp1, "Dmq1": p.Dmq1, "Iqmp": p.Iqmp,
		} {
			if v == nil {
				t.Errorf("RSA 参数 %s 为空", name)
			}
		}
	})

	t.Run("EC", func(t *testing.T) {
		priv, err := GenerateEC(CurveP256)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Params(priv)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type != string(AlgEC) {
			t.Errorf("Type = %q, want EC", p.Type)
		}
		if p.Curve != CurveP256 {
			t.Errorf("Curve = %q, want %q", p.Curve, CurveP256)
		}
		if p.X == nil || p.Y == nil || p.D == nil {
			t.Error("EC 参数不完整")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		priv, err := GenerateEd25519()
		if err != nil {
			t.Fatal(err)
		}
		p, err := Params(priv)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type != string(AlgEd25519) {
			t.Errorf("Type = %q, want ED25519", p.Type)
		}
		// Ed25519 无传统数值参数，应走 RawPrivateKey / RawPublicKey
		if p.N != nil || p.D != nil || p.X != nil {
			t.Error("Ed25519 的 RSA/EC 数值字段应为 nil")
		}
	})
}

// TestParamsPublicKey 验证 Params 对公钥同样可用。
func TestParamsPublicKey(t *testing.T) {
	for _, alg := range []Algorithm{AlgSM2, AlgRSA, AlgEC, AlgEd25519} {
		t.Run(string(alg), func(t *testing.T) {
			var (
				priv PrivateKey
				err  error
			)
			switch alg {
			case AlgSM2:
				priv, err = GenerateSM2()
			case AlgRSA:
				priv, err = GenerateRSA(2048)
			case AlgEC:
				priv, err = GenerateEC(CurveP256)
			case AlgEd25519:
				priv, err = GenerateEd25519()
			}
			if err != nil {
				t.Fatal(err)
			}
			p, err := Params(priv.Public())
			if err != nil {
				t.Fatal(err)
			}
			if p.Type != string(alg) {
				t.Errorf("Type = %q, want %s", p.Type, alg)
			}
		})
	}
}

// TestParamsNilGuard 验证 Params(nil) 报错。
func TestParamsNilGuard(t *testing.T) {
	if _, err := Params(nil); err == nil {
		t.Error("Params(nil) 应报错")
	}
}

// TestMatchAlgorithmAgnostic 验证 Match 对四种算法均可判断配对关系。
func TestMatchAlgorithmAgnostic(t *testing.T) {
	for _, alg := range []Algorithm{AlgSM2, AlgRSA, AlgEC, AlgEd25519} {
		t.Run(string(alg), func(t *testing.T) {
			gen := func() PrivateKey {
				var (
					priv PrivateKey
					err  error
				)
				switch alg {
				case AlgSM2:
					priv, err = GenerateSM2()
				case AlgRSA:
					priv, err = GenerateRSA(2048)
				case AlgEC:
					priv, err = GenerateEC(CurveP256)
				case AlgEd25519:
					priv, err = GenerateEd25519()
				}
				if err != nil {
					t.Fatal(err)
				}
				return priv
			}
			a, b := gen(), gen()

			match, err := Match(a, a.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !match {
				t.Error("私钥与自身公钥应匹配")
			}
			match, err = Match(a, b.Public())
			if err != nil {
				t.Fatal(err)
			}
			if match {
				t.Error("不同密钥不应匹配")
			}
			// 公钥经 PEM 往返后仍应匹配
			pem, err := a.Public().MarshalPublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}
			roundTripped, err := LoadPublicKeyPEM(pem)
			if err != nil {
				t.Fatal(err)
			}
			match, err = Match(a, roundTripped)
			if err != nil {
				t.Fatal(err)
			}
			if !match {
				t.Error("公钥 PEM 往返后应仍匹配")
			}
		})
	}
}

// TestMatchNilGuard 验证 Match 的 nil 处理（返回 false 而非错误）。
func TestMatchNilGuard(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		priv PrivateKey
		pub  PublicKey
	}{
		{"both-nil", nil, nil},
		{"priv-nil", nil, priv.Public()},
		{"pub-nil", priv, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match, err := Match(tc.priv, tc.pub)
			if err != nil {
				t.Fatalf("Match 不应报错：%v", err)
			}
			if match {
				t.Error("含 nil 时不应匹配")
			}
		})
	}
}
