// Package main 演示 ECDH（NIST 曲线与 OKP 曲线）共享密钥派生、PEM 往返与曲线不可用时的降级处理。
//
// 运行（examples 下每个示例都是独立 module）：
//
//	cd examples/ecdh && go run .
//
// Package main demonstrates ECDH shared-secret derivation on NIST and OKP
// curves, PEM round-trips, and graceful degradation when a curve is not
// available at runtime.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/blue-cloud-net/tongsuo-go/crypto/ecdh"
)

func main() {
	// 1. NIST 曲线：P-256 双方派生出一致的共享密钥（原始 X 坐标）。
	p256 := ecdh.P256()
	alice, err := p256.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := p256.GenerateKey()
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

// deriveOKP 在 OKP 曲线上做一次双向派生并打印共享密钥长度。
//
// deriveOKP performs one bidirectional derivation on an OKP curve and prints
// the shared-secret length.
func deriveOKP(curve *ecdh.Curve) error {
	alice, err := curve.GenerateKey()
	if err != nil {
		return err
	}
	bob, err := curve.GenerateKey()
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
