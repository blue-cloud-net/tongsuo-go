// Package main 演示 NTLS（国密 TLCP）双证书回环握手与多轮读写。
//
// NTLS 同时使用两张证书：签名证书（SM2withSM3）+ 加密证书（SM4-GCM-SM3）。
// 本例使用同一密钥对签两张证书（生产环境应使用不同密钥对）。
//
// 运行：
//
//	TONGSUO_HOME=/opt/tongsuo LD_LIBRARY_PATH=${TONGSUO_HOME}/lib64 \
//	CGO_CFLAGS="-I${TONGSUO_HOME}/include" CGO_LDFLAGS="-L${TONGSUO_HOME}/lib64" \
//	go run ./examples/ntls-loopback
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/crypto/sm2"
	"github.com/blue-cloud-net/tongsuo-go/tls"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func main() {
	// 1. 生成签名与加密密钥对（生产环境应分开）
	signPriv, err := sm2.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	encPriv, err := sm2.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// 2. 自签证书
	now := time.Now()
	subject := x509.NewName().Add("CN", "ntls-example.com")
	signCert, err := x509.CreateCertificate(subject, subject, 1,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), signPriv.Public(), signPriv)
	if err != nil {
		log.Fatal(err)
	}
	encCert, err := x509.CreateCertificate(subject, subject, 2,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), encPriv.Public(), encPriv)
	if err != nil {
		log.Fatal(err)
	}

	// 3. NTLS 配置：NTLS=true 表示启用国密双证书
	cfg := &tls.Config{
		NTLS:     true,
		SignCert: signCert,
		SignKey:  signPriv,
		EncCert:  encCert,
		EncKey:   encPriv,
	}

	// 4. 回环 listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Printf("监听地址：%s\n", ln.Addr())

	// 5. 服务端
	srv, err := tls.NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	// 服务端接受连接与回显
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			log.Printf("accept err: %v", err)
			return
		}
		defer raw.Close()

		conn, err := srv.Accept(raw)
		if err != nil {
			log.Printf("server handshake err: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
	}()

	// 6. 客户端拨号 + 多轮读写
	conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		log.Fatalf("client dial err: %v", err)
	}
	defer conn.Close()

	// 类型断言到 *tls.Conn 读取协议版本与套件
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Fatal("not a *tls.Conn")
	}
	fmt.Printf("协商版本：%s\n", tlsConn.Version())
	fmt.Printf("协商套件：%s\n", tlsConn.CipherName())

	// 7. 多轮请求 / 响应
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("第 %d 轮：hello NTLS!\n", i+1)
		if _, err := conn.Write([]byte(msg)); err != nil {
			log.Fatalf("write err: %v", err)
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("read err: %v", err)
		}
		fmt.Printf("收到回显：%s", buf[:n])
	}
	fmt.Println("NTLS 回环测试完成")
}
