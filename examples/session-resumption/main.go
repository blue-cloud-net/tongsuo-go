// Package main 演示 TLS 1.3 握手后票据收集与跨连接恢复。
//
// Package main demonstrates post-handshake TLS 1.3 ticket collection and cross-connection resumption.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/tls"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	key, err := asym.GenerateSM2()
	if err != nil {
		return err
	}
	defer asym.Close(key)
	cert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "session.example"), 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), key.Public(), key)
	if err != nil {
		return err
	}
	defer cert.Close()
	server, err := tls.NewServer(&tls.Config{MinVersion: tls.TLS1_3Version, MaxVersion: tls.TLS1_3Version, Cert: cert, Key: key})
	if err != nil {
		return err
	}
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			raw, err := listener.Accept()
			if err != nil {
				finished <- err
				return
			}
			conn, err := server.Accept(raw)
			if err != nil {
				_ = raw.Close()
				finished <- err
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = conn.Write([]byte("ready")); err == nil {
				ack := make([]byte, 1)
				_, err = io.ReadFull(conn, ack)
			}
			closeErr := conn.Close()
			if err != nil {
				finished <- err
				return
			}
			if closeErr != nil {
				finished <- closeErr
				return
			}
		}
		finished <- nil
	}()
	cache, err := tls.NewSessionCache(8)
	if err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.TLS1_3Version, MaxVersion: tls.TLS1_3Version, Verification: tls.VerifyStrict, RootCAs: []*x509.Certificate{cert}, VerificationName: "session.example", SessionCache: cache}
	for i := 0; i < 2; i++ {
		if err := exchange(listener.Addr().String(), config, i); err != nil {
			return err
		}
	}
	return <-finished
}
func exchange(addr string, config *tls.Config, attempt int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := tls.DialContext(ctx, "tcp", addr, config)
	if err != nil {
		return err
	}
	defer raw.Close()
	conn := raw.(*tls.Conn)
	// TLS 1.3 tickets arrive after the handshake; waiting preserves application bytes.
	session, err := conn.WaitSession(ctx)
	if err != nil {
		return err
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != "ready" {
		return fmt.Errorf("unexpected reply: %q", reply)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}
	state := conn.ConnectionState()
	if state.SessionReused != (attempt == 1) {
		return fmt.Errorf("unexpected reuse on attempt %d", attempt+1)
	}
	fmt.Printf("connection=%d reused=%t ticket=%t\n", attempt+1, state.SessionReused, session.Metadata().HasTicket)
	return nil
}
