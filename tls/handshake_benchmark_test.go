package tls

import (
	"context"
	"net"
	"testing"
	"time"
)

// BenchmarkHandshake 测量完整 TCP/TLS 或 NTLS 握手与显式释放的开销。
//
// BenchmarkHandshake measures complete TCP/TLS or NTLS handshakes and explicit teardown.
func BenchmarkHandshake(b *testing.B) {
	for _, protocol := range []string{"tls12", "tls13", "ntls-ecc", "ntls-ecdhe"} {
		b.Run(protocol, func(b *testing.B) {
			sc, _ := testChainIdentity(b, false)
			cc := &Config{Verification: VerifyNone}
			switch protocol {
			case "tls12":
				sc.MinVersion, sc.MaxVersion = TLS1_2Version, TLS1_2Version
			case "tls13":
				sc.MinVersion = TLS1_3Version
			default:
				sc, _ = testNTLSIdentity(b, "server.example")
				cc, _ = testNTLSIdentity(b, "client.example")
				cc.Verification = VerifyNone
				suite := "ECC-SM2-SM4-GCM-SM3"
				if protocol == "ntls-ecdhe" {
					suite = "ECDHE-SM2-SM4-GCM-SM3"
				}
				sc.CipherSuites, cc.CipherSuites = []string{suite}, []string{suite}
				sc.StrictConfig, cc.StrictConfig = true, true
			}
			srv, err := NewServer(sc)
			if err != nil {
				b.Fatal(err)
			}
			defer srv.Close()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				serverResult := make(chan error, 1)
				go func() {
					raw, err := ln.Accept()
					if err != nil {
						serverResult <- err
						return
					}
					wrapped, err := srv.Accept(raw)
					if err != nil {
						_ = raw.Close()
						serverResult <- err
						return
					}
					err = wrapped.(*Conn).HandshakeContext(ctx)
					_ = wrapped.Close()
					serverResult <- err
				}()
				client, clientErr := DialContext(ctx, "tcp", ln.Addr().String(), cc)
				if client != nil {
					_ = client.Close()
				}
				serverErr := <-serverResult
				cancel()
				if clientErr != nil || serverErr != nil {
					b.Fatalf("client=%v server=%v", clientErr, serverErr)
				}
			}
		})
	}
}
