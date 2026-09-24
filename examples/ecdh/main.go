// Package main 演示 ECDH（NIST 曲线与 OKP 曲线）共享密钥派生、PEM 往返与曲线不可用时的降级处理。
//
// 运行（examples 下每个示例都是独立 module）：
//
//	cd examples/ecdh && go run .
//
// 包结构提示：密钥**生成**在 `asym` 包（`GenerateEC` / `GenerateX25519` /
// `GenerateX448`），**协商**在 `ecdh` 包（`LoadPrivateKey` / `SharedSecret` /
// `(*PrivateKey).ECDH`）。`ecdh.LoadPrivateKey` 会复制一份底层句柄，因此包装完成后
// 即可释放 `asym` 侧密钥（下方 `newKey` 演示了这一顺序）。
//
// Package main demonstrates ECDH shared-secret derivation on NIST and OKP
// curves, PEM round-trips, and graceful degradation when a curve is not
// available at runtime.
//
// Key generation lives in package asym (GenerateEC / GenerateX25519 /
// GenerateX448) while key agreement lives in package ecdh (LoadPrivateKey /
// SharedSecret / (*PrivateKey).ECDH). ecdh.LoadPrivateKey duplicates the
// underlying handle, so the asym-side key may be released right after wrapping
// (newKey below demonstrates that order).
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/ecdh"
)

func main() {
	// 1. NIST 曲线：P-256 双方派生出一致的共享密钥（原始 X 坐标）。
	p256 := ecdh.P256()
	alice, err := newKey(p256)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := newKey(p256)
	if err != nil {
		log.Fatal(err)
	}
	aliceShared, err := alice.ECDH(bob.Public())
	if err != nil {
		log.Fatal(err)
	}
	bobShared, err := bob.ECDH(alice.Public())
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(aliceShared, bobShared) {
		log.Fatal("P-256 双向派生不一致")
	}
	fmt.Printf("P-256   共享密钥 %d 字节，双向一致 ✓\n", len(aliceShared))

	// 2. PEM 往返：私钥（PKCS#8）导出后可重新加载，派生结果不变。
	privPEM, err := alice.MarshalPEM()
	if err != nil {
		log.Fatal(err)
	}
	reloaded, err := ecdh.LoadPrivateKeyPEM(p256, privPEM)
	if err != nil {
		log.Fatal(err)
	}
	reloadedShared, err := reloaded.ECDH(bob.Public())
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(aliceShared, reloadedShared) {
		log.Fatal("P-256 私钥 PEM 往返后派生结果变化")
	}
	fmt.Println("P-256   私钥 PEM 往返后派生一致 ✓")

	// 3. OKP 曲线：X25519（32 字节共享密钥）。
	if err := deriveOKP(ecdh.X25519()); err != nil {
		log.Fatal(err)
	}

	// 4. OKP 曲线：X448（56 字节共享密钥）——是否可用取决于运行时铜锁
	//    provider，不支持时打印提示并跳过，而不是直接失败。
	if err := deriveOKP(ecdh.X448()); err != nil {
		fmt.Printf("X448    不可用（%v），已跳过\n", err)
		return
	}
	fmt.Println("提示：共享密钥属敏感数据，使用完毕请自行清零")
}

// newKey 按曲线生成一对协商用密钥。
//
// 生成走 asym（asym 不暴露底层句柄），包装走 ecdh；包装会复制句柄，故包装完成后
// 立刻释放 asym 侧密钥，避免只依赖 finalizer。
//
// newKey generates a key pair for the given curve.
//
// Generation goes through asym (which does not expose its underlying handle) and
// wrapping through ecdh; the wrap duplicates the handle, so the asym-side key is
// released immediately afterwards rather than relying on the finalizer.
func newKey(c *ecdh.Curve) (*ecdh.PrivateKey, error) {
	var (
		priv asym.PrivateKey
		err  error
	)
	// ecdh.Curve 只暴露展示名（"P-256" / "X25519" …），而 asym.GenerateEC 吃的是
	// OpenSSL 曲线名（"prime256v1" …），故此处显式对照。
	switch c.Name() {
	case "P-256":
		priv, err = asym.GenerateEC(asym.CurveP256)
	case "P-384":
		priv, err = asym.GenerateEC(asym.CurveP384)
	case "P-521":
		priv, err = asym.GenerateEC(asym.CurveP521)
	case "secp256k1":
		priv, err = asym.GenerateEC(asym.CurveSecp256k1)
	case "X25519":
		priv, err = asym.GenerateX25519()
	case "X448":
		priv, err = asym.GenerateX448()
	default:
		return nil, fmt.Errorf("未支持的曲线：%s", c.Name())
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = asym.Close(priv) }()
	return ecdh.LoadPrivateKey(priv)
}

// deriveOKP 在 OKP 曲线上做一次双向派生并打印共享密钥长度。
//
// deriveOKP performs one bidirectional derivation on an OKP curve and prints
// the shared-secret length.
func deriveOKP(curve *ecdh.Curve) error {
	alice, err := newKey(curve)
	if err != nil {
		return err
	}
	bob, err := newKey(curve)
	if err != nil {
		return err
	}
	aliceShared, err := alice.ECDH(bob.Public())
	if err != nil {
		return err
	}
	bobShared, err := bob.ECDH(alice.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(aliceShared, bobShared) {
		return fmt.Errorf("%s 双向派生不一致", curve.Name())
	}
	fmt.Printf("%-7s 共享密钥 %d 字节，双向一致 ✓\n", curve.Name(), len(aliceShared))
	return nil
}
