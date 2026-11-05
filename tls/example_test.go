package tls_test

import (
	"fmt"
	"net"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
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
	signPriv, _ := asym.GenerateSM2()
	encPriv, _ := asym.GenerateSM2()

	defer asym.Close(signPriv)
	defer asym.Close(encPriv)

	// 自签证书（实际应用：CA 签发）
	now := time.Now()
	subject := x509.NewName().Add("CN", "example.com")
	build := func(priv asym.PrivateKey, serial int64, usage string) (*x509.Certificate, error) {
		cert := x509.NewCertificate()
		steps := []func() error{
			func() error { return cert.SetVersion(2) },
			func() error { return cert.SetSerial(serial) },
			func() error { return cert.SetSubject(subject) },
			func() error { return cert.SetIssuer(subject) },
			func() error { return cert.SetValidity(now.Add(-time.Hour), now.Add(365*24*time.Hour)) },
			func() error { return cert.SetPublicKey(priv.Public()) },
			func() error { return cert.AddKeyUsage(usage) },
			func() error { return cert.Sign(priv) },
		}
		for _, step := range steps {
			if err := step(); err != nil {
				cert.Close()
				return nil, err
			}
		}
		return cert, nil
	}
	signCert, err := build(signPriv, 1, "critical,digitalSignature")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer signCert.Close()
	encCert, err := build(encPriv, 2, "critical,keyEncipherment,dataEncipherment,keyAgreement")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer encCert.Close()

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
		if tc, ok := conn.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
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
