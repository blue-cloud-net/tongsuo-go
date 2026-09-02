package tls_test

import (
	"fmt"
	"net"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/tls"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)
// ExampleDial 演示 NTLS（国密 TLCP）双证书回环握手。
//
// 需要生成 4 个密钥：签名 + 加密 × 私钥 + 证书。本例同密钥对两证（生产环境应分开）。
// 客户端通过 Dial 握手；服务端通过 NewServer + Accept 握手。
// 握手完成后双方可 Read/Write；关闭任一端即释放。
//
// ExampleDial demonstrates an NTLS (GM/T 0024 TLCP) dual-certificate loopback handshake.
//
// The example generates the signing and encryption key pairs and self-signed
// certificates, then performs a handshake on a loopback socket. Production
// deployments should keep the signing and encryption keys distinct.
func ExampleDial() {
	// 生成密钥
	signPriv, _ := sm2.GenerateKey()
	encPriv, _ := sm2.GenerateKey()

	// 自签证书（实际应用：CA 签发）
	now := time.Now()
	subject := x509.NewName().Add("CN", "example.com")
	signCert, _ := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), signPriv.Public(), signPriv)
	encCert, _ := x509.CreateCertificate(subject, subject, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), encPriv.Public(), encPriv)

	cfg := &tls.Config{
		NTLS:     true,
		SignCert: signCert, SignKey: signPriv,
		EncCert: encCert, EncKey: encPriv,
	}

	// 回环 listener
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	// 服务端
	srv, _ := tls.NewServer(cfg)
	defer srv.Close()
	go func() {
		raw, _ := ln.Accept()
		conn, _ := srv.Accept(raw)
		_ = conn
	}()

	// 客户端
	c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		fmt.Println("dial err:", err)
		return
	}
	defer c.Close()

	// 双方版本与套件
	cc, ok := c.(*tls.Conn)
	if !ok {
		fmt.Println("not tls.Conn")
		return
	}
	fmt.Println(cc.Version() != "") // 非空即握手成功
	// Output: true
}
