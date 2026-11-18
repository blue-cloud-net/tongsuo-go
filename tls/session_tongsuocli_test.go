//go:build tongsuocli

package tls

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestSessionCLIInterop 检查原生会话编码和 SDK/CLI 双向恢复。
//
// TestSessionCLIInterop checks native session encoding and bidirectional SDK/CLI resumption.
func TestSessionCLIInterop(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	for _, version := range []uint16{TLS1_2Version, TLS1_3Version} {
		t.Run(map[uint16]string{TLS1_2Version: "TLS12", TLS1_3Version: "TLS13"}[version], func(t *testing.T) {
			sc, ca := testChainIdentity(t, false)
			sc.MinVersion, sc.MaxVersion = version, version
			manager, err := NewTicketKeyManager()
			if err != nil {
				t.Fatal(err)
			}
			old, err := GenerateTicketKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.SetKeys([]TicketKey{old}); err != nil {
				t.Fatal(err)
			}
			sc.TicketKeys = manager
			cc := &Config{MinVersion: version, MaxVersion: version, ServerName: "leaf.example", VerificationName: "leaf.example", Verification: VerifyStrict, RootCAs: []*x509.Certificate{ca}}
			addr, accept := sessionEndpoint(t, sc)
			c, err := sessionDial(t, addr, cc)
			s := accept()
			if err != nil || s.err != nil {
				t.Fatalf("%v %v", err, s.err)
			}
			state := receiveSession(t, c, s.conn)
			_ = c.Close()
			_ = s.conn.Close()
			der, err := state.MarshalDER()
			if err != nil {
				t.Fatal(err)
			}
			converted, err := testutil.RunOpenSSL([]string{"sess_id", "-inform", "DER", "-outform", "PEM"}, der)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseSessionPEM(converted)
			if err != nil {
				t.Fatal(err)
			}
			back, err := parsed.MarshalDER()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(der, back) {
				t.Fatal("CLI DER/PEM conversion changed session")
			}
			fresh, err := GenerateTicketKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.SetKeys([]TicketKey{fresh, old}); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "sdk.pem")
			output := filepath.Join(dir, "cli.pem")
			cafile := filepath.Join(dir, "ca.pem")
			if err := os.WriteFile(input, converted, 0600); err != nil {
				t.Fatal(err)
			}
			capem, err := ca.MarshalPEM()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cafile, capem, 0600); err != nil {
				t.Fatal(err)
			}
			flag := "-tls1_2"
			if version == TLS1_3Version {
				flag = "-tls1_3"
			}
			type cliResult struct {
				out []byte
				err error
			}

			for _, resume := range []bool{true, false} {
				result := make(chan cliResult, 1)
				args := []string{"s_client", "-connect", addr, "-servername", "leaf.example", "-CAfile", cafile, "-verify_hostname", "leaf.example", flag, "-sess_out", output, "-ign_eof"}
				if resume {
					args = append(args, "-sess_in", input)
				}
				go func() { out, err := testutil.RunOpenSSLCombined(args, nil); result <- cliResult{out, err} }()
				server := accept()
				if server.err != nil {
					t.Fatal(server.err)
				}
				if server.conn.ConnectionState().SessionReused != resume {
					t.Fatalf("CLI reuse expected %v", resume)
				}
				if _, err := server.conn.Write([]byte("ticket exchange\n")); err != nil {
					t.Fatal(err)
				}
				_ = server.conn.Close()
				select {
				case r := <-result:
					if r.err != nil {
						t.Fatalf("s_client: %v\n%s", r.err, r.out)
					}
					if strings.Contains(string(r.out), "Reused,") != resume {
						t.Fatalf("CLI reported unexpected reuse: %s", r.out)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("CLI failed to terminate")
				}
			}

			cliPEM, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			fromCLI, err := ParseSessionPEM(cliPEM)
			if err != nil {
				t.Fatal(err)
			}
			fromCLI, err = fromCLI.WithPeerCertificates(state.peers)
			if err != nil {
				t.Fatal(err)
			}
			cc.Session = fromCLI
			c, err = sessionDial(t, addr, cc)
			s = accept()
			if err != nil || s.err != nil {
				t.Fatalf("CLI to SDK: %v %v", err, s.err)
			}
			if !c.ConnectionState().SessionReused || !s.conn.ConnectionState().SessionReused {
				t.Fatal("SDK did not resume CLI session")
			}
		})
	}
}
