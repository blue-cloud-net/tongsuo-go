//go:build tongsuocli

package tls

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func TestCLIRequiredOCSP(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	dir := t.TempDir()
	run := func(args ...string) { testutil.MustRunOpenSSLInDir(t, dir, args...) }
	run("req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=OCSP Test CA", "-days", "2")
	run("req", "-new", "-nodes", "-newkey", "rsa:2048", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=leaf.example")
	run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "10", "-out", "leaf.pem", "-days", "1")
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write("index.txt", "V\t491231235959Z\t\t0A\tunknown\t/CN=leaf.example\n")
	respond := func(out, identity string) {
		run("ocsp", "-index", "index.txt", "-rsigner", identity+".pem", "-rkey", identity+".key", "-CA", "ca.pem", "-issuer", "ca.pem", "-cert", "leaf.pem", "-respout", out, "-noverify")
	}
	respond("good.der", "ca")
	respond("unauthorized.der", "leaf")
	write("index.txt", "R\t491231235959Z\t260101000000Z\t0A\tunknown\t/CN=leaf.example\n")
	respond("revoked.der", "ca")
	loadCert := func(name string) *x509.Certificate {
		t.Helper()
		cert, err := x509.LoadCertificatePEM(read(name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cert.Close() })
		return cert
	}
	root, leaf := loadCert("ca.pem"), loadCert("leaf.pem")
	key, err := asym.LoadPrivateKeyPEM(read("leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer asym.Close(key)
	manager, err := NewTicketKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	sc := &Config{Cert: leaf, Key: key, OCSPStaple: read("good.der"), TicketKeys: manager, MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version}
	cc := &Config{RootCAs: []*x509.Certificate{root}, ServerName: "leaf.example", Verification: VerifyStrict, OCSPPolicy: OCSPRequire, MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version}
	first, _, ce, se := handshakePair(t, sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("first handshake: %v / %v", ce, se)
	}
	if state := first.ConnectionState(); !state.OCSPStapled || state.OCSPVerification != VerificationPassed {
		t.Fatal("staple not verified")
	}
	session, err := first.SessionState()
	if err != nil {
		t.Fatal(err)
	}
	// handshakePair creates a new endpoint, so import auxiliary data to
	// exercise revalidation independently of the original endpoint binding.
	native, err := session.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(native)
	imported, err := ParseSessionDER(native)
	if err != nil {
		t.Fatal(err)
	}
	imported, err = imported.WithPeerCertificates(first.ConnectionState().PeerCertificates)
	if err != nil {
		t.Fatal(err)
	}
	cc.Session, err = imported.WithOCSPResponse(sc.OCSPStaple)
	if err != nil {
		t.Fatal(err)
	}
	sc.OCSPStaple = nil
	resumed, _, ce, se := handshakePair(t, sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("resumed handshake: %v / %v", ce, se)
	}
	state := resumed.ConnectionState()
	if !state.SessionReused || state.OCSPStapled || !state.OCSPFromSession || state.OCSPVerification != VerificationPassed {
		t.Fatalf("unexpected restored state: reused=%t stapled=%t cached=%t verification=%v", state.SessionReused, state.OCSPStapled, state.OCSPFromSession, state.OCSPVerification)
	}

	for _, name := range []string{"unauthorized.der", "revoked.der"} {
		t.Run(name, func(t *testing.T) {
			sc, cc := sc.Clone(), cc.Clone()
			cc.Session = nil
			sc.OCSPStaple = read(name)
			_, _, ce, _ := handshakePair(t, sc, cc)
			if ce == nil {
				t.Fatal("invalid staple accepted")
			}
		})
	}
	t.Run("invalid cache falls back", func(t *testing.T) {
		sc, cc := sc.Clone(), cc.Clone()
		sc.OCSPStaple = read("good.der")
		var err error
		cc.Session, err = imported.WithOCSPResponse(read("revoked.der"))
		if err != nil {
			t.Fatal(err)
		}
		full, _, ce, se := handshakePair(t, sc, cc)
		if ce != nil || se != nil {
			t.Fatalf("full handshake: %v / %v", ce, se)
		}
		state := full.ConnectionState()
		if state.SessionReused || !state.OCSPStapled || state.OCSPVerification != VerificationPassed {
			t.Fatal("did not fall back to a verified full handshake")
		}
	})
	t.Run("TLS13", func(t *testing.T) {
		sc, cc := sc.Clone(), cc.Clone()
		sc.MinVersion, sc.MaxVersion = TLS1_3Version, TLS1_3Version
		cc.MinVersion, cc.MaxVersion = TLS1_3Version, TLS1_3Version
		cc.Session = nil
		cc.SessionCache, err = NewSessionCache(4)
		if err != nil {
			t.Fatal(err)
		}
		sc.OCSPStaple = read("good.der")
		addr, accept := sessionEndpoint(t, sc)
		first, err := sessionDial(t, addr, cc)
		server := accept()
		if err != nil || server.err != nil {
			t.Fatalf("first TLS13 handshake: %v / %v", err, server.err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := first.WaitSession(ctx); err != nil {
			t.Fatal(err)
		}
		resumed, err := sessionDial(t, addr, cc)
		server = accept()
		if err != nil || server.err != nil {
			t.Fatalf("resumed TLS13 handshake: %v / %v", err, server.err)
		}
		state := resumed.ConnectionState()
		if !state.SessionReused || !state.OCSPFromSession || state.OCSPVerification != VerificationPassed {
			t.Fatalf("unexpected TLS13 resumption: reused=%t cached=%t verification=%v", state.SessionReused, state.OCSPFromSession, state.OCSPVerification)
		}
	})

}
