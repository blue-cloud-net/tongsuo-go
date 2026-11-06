package tls_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/tls"
)

// ExampleClient 演示有期限的握手探测，失败时仍读取状态，最后释放连接。
//
// ExampleClient demonstrates a bounded handshake probe that reads state even on failure and closes the connection.
func ExampleClient() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:4433")
	if err != nil {
		fmt.Println(err)
		return
	}
	conn, err := tls.Client(raw, &tls.Config{
		Protocol:         tls.ProtocolTLS,
		Verification:     tls.VerifyReport,
		ServerName:       "route.example",
		VerificationName: "server.example",
		NextProtos:       []string{"http/1.1"},
	})
	if err != nil {
		_ = raw.Close()
		fmt.Println(err)
		return
	}
	defer conn.Close()
	err = conn.HandshakeContext(ctx)
	state := conn.ConnectionState()
	fmt.Println(state.HandshakeComplete, state.Verification, state.CipherName, err)
	// VerifyReport permits untrusted peers; authenticated connections use
	// VerifyStrict with explicit RootCAs. A completed handshake alone is not trust.
}
