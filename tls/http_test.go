package tls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func TestHTTPTransportAndServe(t *testing.T) {
	for _, protocol := range []string{"TLS12", "TLS13", "NTLS", "RFC8998-GCM", "RFC8998-CCM"} {
		t.Run(protocol, func(t *testing.T) {
			cfg, root := testChainIdentity(t, false)
			clientCfg := &Config{RootCAs: []*x509.Certificate{root}, VerificationName: "leaf.example"}
			switch protocol {
			case "TLS12":
				cfg.MinVersion, cfg.MaxVersion = TLS1_2Version, TLS1_2Version
			case "TLS13":
				cfg.MinVersion, cfg.MaxVersion = TLS1_3Version, TLS1_3Version
			case "NTLS":
				cfg, root = testNTLSIdentity(t, "ntls.example")
				clientCfg = &Config{NTLS: true, RootCAs: []*x509.Certificate{root}, VerificationName: "ntls.example"}
			default:
				cfg = rfc8998Identity(t)
				suite := "TLS_SM4_GCM_SM3"
				if protocol == "RFC8998-CCM" {
					suite = "TLS_SM4_CCM_SM3"
				}
				cfg.CipherSuites = []string{suite}
				clientCfg = &Config{RFC8998: true, CipherSuites: []string{suite}, RootCAs: []*x509.Certificate{cfg.Cert}, VerificationName: "rfc8998.example"}
			}
			testHTTPTransportAndServe(t, cfg, clientCfg)
		})
	}
}

func testHTTPTransportAndServe(t *testing.T, cfg, clientCfg *Config) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, ok := HTTPConnectionState(r.Context())
		if !ok || state.NegotiatedProtocol != "http/1.1" {
			http.Error(w, "missing HTTP/1.1 TLS state", 500)
			return
		}
		_, _ = io.Copy(w, r.Body)
	})}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- ServeTLS(server, ln, cfg) }()
	slow, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	tr, err := NewHTTPTransport(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for i := 0; i < 2; i++ {
		reused := false
		method, payload := http.MethodPost, "echo"
		if i == 1 {
			method, payload = http.MethodGet, ""
		}
		req, err := http.NewRequest(method, "https://"+ln.Addr().String(), strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != payload || reused != (i == 1) {
			t.Fatalf("status=%d body=%q reused=%v err=%v", resp.StatusCode, body, reused, err)
		}
	}
	if _, err := client.Get("http://" + ln.Addr().String()); err == nil {
		t.Fatal("accepted plaintext HTTP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("ServeTLS: %v", err)
	}
}

func TestHTTPTransportCancelsStalledHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tr, err := NewHTTPTransport(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RoundTrip: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request did not return")
	}
}
