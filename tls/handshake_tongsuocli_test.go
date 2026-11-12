//go:build tongsuocli

package tls

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func handshakeCLIFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCLIHandshakeAuthentication 验证 TLS/NTLS 客户端与 CLI 的双向认证、ALPN 和状态。
//
// TestCLIHandshakeAuthentication verifies TLS/NTLS mutual authentication, ALPN and state against the CLI.
func TestCLIHandshakeAuthentication(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	for _, protocol := range []string{"tls12", "tls13", "ntls-ecc", "ntls-ecdhe", "rfc8998-gcm", "rfc8998-ccm", "rfc8998-gcm-oneway", "rfc8998-ccm-oneway"} {
		t.Run(protocol, func(t *testing.T) {
			var sc, cc *Config
			var serverCA, clientCA *x509.Certificate
			ntls := strings.HasPrefix(protocol, "ntls")
			rfc := strings.HasPrefix(protocol, "rfc8998")
			oneWay := strings.HasSuffix(protocol, "oneway")
			versionFlag := "-tls1_2"
			if protocol == "tls13" {
				versionFlag = "-tls1_3"
			}
			suite := "ECC-SM2-SM4-GCM-SM3"
			if protocol == "ntls-ecdhe" {
				suite = "ECDHE-SM2-SM4-GCM-SM3"
			}
			if rfc {
				sc, cc = rfc8998Identity(t), rfc8998Identity(t)
				serverCA, clientCA = sc.Cert, cc.Cert
			} else if ntls {
				sc, serverCA = testNTLSIdentity(t, "ntls.example")
				cc, clientCA = testNTLSIdentity(t, "client.example")
			} else {
				sc, serverCA = testChainIdentity(t, false)
				cc, clientCA = testChainIdentity(t, false)
			}
			sc.NextProtos = []string{"interop/1"}
			sc.ClientAuth = RequireAndVerifyClientCert
			sc.ClientCAs = []*x509.Certificate{clientCA}
			cc.NextProtos = []string{"interop/1"}
			cc.RootCAs = []*x509.Certificate{serverCA}
			cc.Verification = VerifyStrict
			cc.ServerName = "leaf.example"
			if ntls {
				cc.ServerName = "ntls.example"
				sc.CipherSuites = []string{suite}
				cc.CipherSuites = []string{suite}
				sc.StrictConfig = true
				cc.StrictConfig = true
			} else if protocol == "tls12" {
				sc.MaxVersion = TLS1_2Version
				cc.MaxVersion = TLS1_2Version
			} else {
				sc.MinVersion = TLS1_3Version
				cc.MinVersion = TLS1_3Version
			}
			if rfc {
				suite = "TLS_SM4_GCM_SM3"
				if strings.Contains(protocol, "ccm") {
					suite = "TLS_SM4_CCM_SM3"
				}
				sc.CipherSuites, cc.CipherSuites = []string{suite}, []string{suite}
				cc.ServerName = "rfc8998.example"
				if oneWay {
					sc.ClientAuth = NoClientCert
					cc.Cert = nil
					cc.Key = nil
				}
			}
			dir := t.TempDir()
			caServer := handshakeCLIFile(t, dir, "server-ca.pem", mustPEM(t, serverCA))
			caClient := handshakeCLIFile(t, dir, "client-ca.pem", mustPEM(t, clientCA))
			credentials := func(cfg *Config, prefix string) []string {
				if !cfg.NTLS && cfg.Cert == nil {
					return nil
				}
				if cfg.NTLS {
					return []string{"-sign_cert", handshakeCLIFile(t, dir, prefix+"-sign.pem", mustPEM(t, cfg.SignCert)), "-sign_key", handshakeCLIFile(t, dir, prefix+"-sign-key.pem", mustKeyPEM(t, cfg.SignKey)), "-enc_cert", handshakeCLIFile(t, dir, prefix+"-enc.pem", mustPEM(t, cfg.EncCert)), "-enc_key", handshakeCLIFile(t, dir, prefix+"-enc-key.pem", mustKeyPEM(t, cfg.EncKey))}
				}
				chain := []byte{}
				for _, cert := range cfg.CertChain {
					chain = append(chain, mustPEM(t, cert)...)
				}
				args := []string{"-cert", handshakeCLIFile(t, dir, prefix+".pem", mustPEM(t, cfg.Cert)), "-key", handshakeCLIFile(t, dir, prefix+"-key.pem", mustKeyPEM(t, cfg.Key))}
				if len(chain) > 0 {
					args = append(args, "-cert_chain", handshakeCLIFile(t, dir, prefix+"-chain.pem", chain))
				}
				return args
			}
			protocolArgs := []string{versionFlag}
			if rfc {
				protocolArgs = []string{"-tls1_3", "-enable_sm_tls13_strict", "-ciphersuites", suite, "-groups", "curveSM2", "-sigalgs", "sm2sig_sm3"}
			}
			if ntls {
				protocolArgs = []string{"-ntls", "-enable_ntls", "-cipher", suite}
			}
			t.Run("cli-client", func(t *testing.T) {
				srv, err := NewServer(sc)
				if err != nil {
					t.Fatal(err)
				}
				defer srv.Close()
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				done := make(chan error, 1)
				go func() {
					raw, err := ln.Accept()
					if err != nil {
						done <- err
						return
					}
					conn, err := srv.Accept(raw)
					if err != nil {
						_ = raw.Close()
						done <- err
						return
					}
					defer conn.Close()
					c := conn.(*Conn)
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					if err := c.Handshake(); err != nil {
						done <- err
						return
					}
					state := c.ConnectionState()
					wantVerification := VerificationPassed
					if oneWay {
						wantVerification = VerificationNotPerformed
					}
					if state.Verification != wantVerification || state.NegotiatedProtocol != "interop/1" {
						done <- fmt.Errorf("invalid authentication state: %+v", state)
						return
					}
					msg := make([]byte, 4)
					if _, err := io.ReadFull(c, msg); err != nil {
						done <- err
						return
					}
					if string(msg) != "ping" {
						done <- fmt.Errorf("invalid request %q", msg)
						return
					}
					_, err = c.Write([]byte("pong"))
					done <- err
				}()
				args := append([]string{"s_client", "-connect", ln.Addr().String(), "-quiet", "-ign_eof", "-verify_return_error", "-CAfile", caServer, "-verify_hostname", cc.ServerName, "-servername", cc.ServerName, "-alpn", "interop/1"}, protocolArgs...)
				args = append(args, credentials(cc, "client")...)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, testutil.OpenSSLBin(), args...)
				cmd.Stdin = bytes.NewBufferString("ping")
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("CLI client: %v\n%s", err, out)
				}
				if !bytes.Contains(out, []byte("pong")) {
					t.Fatalf("response=%q", out)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
			t.Run("cli-server", func(t *testing.T) {
				reserve, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := reserve.Addr().String()
				_ = reserve.Close()
				args := append([]string{"s_server", "-accept", addr, "-quiet", "-www", "-Verify", "4", "-verify_return_error", "-CAfile", caClient, "-alpn", "interop/1"}, protocolArgs...)
				if oneWay {
					cleaned := make([]string, 0, len(args))
					for i := 0; i < len(args); i++ {
						if args[i] == "-Verify" {
							i++
							continue
						}
						cleaned = append(cleaned, args[i])
					}
					args = cleaned
				}
				args = append(args, credentials(sc, "server")...)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, testutil.OpenSSLBin(), args...)
				var output bytes.Buffer
				cmd.Stderr = &output
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
				var conn net.Conn
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					conn, err = DialContext(ctx, "tcp", addr, cc)
					if err == nil {
						break
					}
					time.Sleep(30 * time.Millisecond)
				}
				if err != nil {
					t.Fatalf("CLI server handshake: %v", err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				state := conn.(*Conn).ConnectionState()
				if state.Verification != VerificationPassed || state.NegotiatedProtocol != "interop/1" {
					t.Fatalf("state=%+v", state)
				}
				if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(buf[:n], []byte("200 ok")) {
					t.Fatalf("response=%q", buf[:n])
				}
			})
		})
	}
}
