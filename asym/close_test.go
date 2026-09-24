package asym_test

import (
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/asym"
)

// TestCloseNil 验证 Close(nil) 为安全 no-op。
//
// TestCloseNil verifies that Close(nil) is a safe no-op.
func TestCloseNil(t *testing.T) {
	if err := asym.Close(nil); err != nil {
		t.Errorf("Close(nil) = %v, want nil", err)
	}
}

// TestCloseReleasesHandle 验证 Close 真的释放句柄：释放后使用该密钥报错，且重复
// 调用幂等。
//
// TestCloseReleasesHandle verifies that Close really releases the handle: using
// the key afterwards fails, and repeated calls are idempotent.
func TestCloseReleasesHandle(t *testing.T) {
	priv, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	// 释放前可用
	if _, err := priv.MarshalPrivateKeyPEM(); err != nil {
		t.Fatalf("释放前导出私钥失败：%v", err)
	}

	if err := asym.Close(priv); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// 幂等
	if err := asym.Close(priv); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}

	// 释放后必须报错（而不是崩溃或静默返回零值）
	_, err = priv.MarshalPrivateKeyPEM()
	if err == nil {
		t.Fatal("Close 后仍可导出私钥 PEM —— 句柄未真正释放")
	}
	if _, err := asym.SignECDSA(priv, []byte("msg")); err == nil {
		t.Error("Close 后 SignECDSA 应报错")
	}
}

// TestCloseAllAlgorithms 验证 7 种算法的私钥都能经 Close 释放，并锁定一个容易踩的
// 语义：priv.Public() 返回的是**共享同一底层句柄**的别名（不 Dup），因此对别名
// 调用 Close 即释放该共享句柄，私钥也随之失效；随后再 Close 私钥只是幂等 no-op。
//
// 需要「副本/别名销毁不影响原件」的语义时，应经 internal/keyaccess 取句柄后
// EVP_PKEY_dup（下游 ecdh 就是这么做的），而不是依赖 Public()。
//
// TestCloseAllAlgorithms verifies that all seven algorithms' private keys can be
// released and pins down an easy-to-trip semantic: priv.Public() returns an alias
// **sharing the same handle** (no Dup), so closing the alias releases the shared
// handle and the private key becomes unusable too; the subsequent Close on the
// private key is merely an idempotent no-op.
func TestCloseAllAlgorithms(t *testing.T) {
	gen := map[string]func() (asym.PrivateKey, error){
		"SM2":     func() (asym.PrivateKey, error) { return asym.GenerateSM2() },
		"RSA":     func() (asym.PrivateKey, error) { return asym.GenerateRSA(2048) },
		"EC":      func() (asym.PrivateKey, error) { return asym.GenerateEC(asym.CurveP256) },
		"Ed25519": func() (asym.PrivateKey, error) { return asym.GenerateEd25519() },
		"Ed448":   func() (asym.PrivateKey, error) { return asym.GenerateEd448() },
		"X25519":  func() (asym.PrivateKey, error) { return asym.GenerateX25519() },
		"X448":    func() (asym.PrivateKey, error) { return asym.GenerateX448() },
	}
	for name, f := range gen {
		t.Run(name, func(t *testing.T) {
			priv, err := f()
			if err != nil {
				t.Fatalf("generate %s: %v", name, err)
			}
			pub := priv.Public()
			if pub == nil {
				t.Fatalf("%s.Public() = nil", name)
			}
			// 别名可用
			if _, err := pub.MarshalPublicKeyPEM(); err != nil {
				t.Fatalf("%s 公钥导出失败：%v", name, err)
			}

			// 释放别名 = 释放共享句柄
			if err := asym.Close(pub); err != nil {
				t.Fatalf("Close(pub): %v", err)
			}
			if _, err := pub.MarshalPublicKeyPEM(); err == nil {
				t.Errorf("%s：Close(pub) 后公钥仍可用", name)
			}
			if _, err := priv.MarshalPrivateKeyPEM(); err == nil {
				t.Errorf("%s：Public() 应共享句柄，Close(pub) 后私钥应一并失效", name)
			}

			// 再释放私钥：幂等 no-op，不报错
			if err := asym.Close(priv); err != nil {
				t.Fatalf("%s：共享句柄已释放，Close(priv) 应为幂等 no-op，实际 %v", name, err)
			}
		})
	}
}

// TestCloseOnlyOnceForAliasedPair 验证只释放一次即足够（先私钥后别名）。
//
// TestCloseOnlyOnceForAliasedPair verifies that releasing once suffices
// (private key first, alias second).
func TestCloseOnlyOnceForAliasedPair(t *testing.T) {
	priv, err := asym.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	if err := asym.Close(priv); err != nil {
		t.Fatalf("Close(priv): %v", err)
	}
	if err := asym.Close(pub); err != nil {
		t.Fatalf("别名与私钥共享句柄，二次 Close 应幂等，实际 %v", err)
	}
	if _, err := pub.MarshalPublicKeyPEM(); err == nil {
		t.Error("共享句柄已释放，公钥应不可用")
	}
}

// TestCloseIsNotAnErrorBeforeUse 验证加载得到的密钥也能正常释放（构造与加载两条
// 路径都持句柄）。
//
// TestCloseIsNotAnErrorBeforeUse verifies that loaded keys can also be released
// (both the constructed and the loaded path own a handle).
func TestCloseIsNotAnErrorBeforeUse(t *testing.T) {
	src, err := asym.GenerateEC(asym.CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := src.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := asym.Close(src); err != nil {
		t.Fatal(err)
	}

	loaded, err := asym.LoadPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := asym.Close(loaded); err != nil {
		t.Fatalf("Close(loaded): %v", err)
	}
	// 二次释放仍安全
	if err := asym.Close(loaded); err != nil {
		t.Fatalf("重复 Close(loaded): %v", err)
	}
}
