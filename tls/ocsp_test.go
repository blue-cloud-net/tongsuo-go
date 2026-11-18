package tls

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func TestOCSPStapleCapture(t *testing.T) {
	sc := testServerConfig(t)
	want := []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
	leaf, err := sc.Cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	sc.GetOCSPStaple = func(cert []byte) ([]byte, error) {
		if !bytes.Equal(cert, leaf) {
			return nil, errors.New("wrong selected certificate")
		}
		return want, nil
	}
	cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert},
		ServerName: "server.tongsuo-go.dev", RequestOCSP: true}
	c, _, ce, se := handshakePair(t, sc, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	state := c.ConnectionState()
	if !state.OCSPStapled || !bytes.Equal(state.OCSPResponse, want) || state.OCSPVerification != VerificationNotPerformed {
		t.Fatalf("unexpected OCSP state: %t %x %v", state.OCSPStapled, state.OCSPResponse, state.OCSPVerification)
	}
	state.OCSPResponse[0] ^= 0xff
	if !bytes.Equal(c.ConnectionState().OCSPResponse, want) {
		t.Fatal("mutable connection snapshot")
	}
}

func TestOCSPRequireMissing(t *testing.T) {
	sc := testServerConfig(t)
	cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert},
		ServerName: "server.tongsuo-go.dev", OCSPPolicy: OCSPRequire}
	_, _, ce, _ := handshakePair(t, sc, cc)
	if ce == nil {
		t.Fatal("missing staple accepted")
	}
}

func TestOCSPTimeWithoutNextUpdate(t *testing.T) {
	now := time.Unix(1720000000, 0)
	for _, tc := range []struct {
		age   time.Duration
		valid bool
	}{
		{time.Hour, true}, {25 * time.Hour, false}, {-time.Hour, false},
	} {
		update := now.Add(-tc.age)
		err := checkOCSPTime(&x509.Response{ThisUpdate: update, ProducedAt: update}, now)
		if (err == nil) != tc.valid {
			t.Fatalf("age %s: %v", tc.age, err)
		}
	}
}

func TestOCSPStapleProtocolMatrix(t *testing.T) {
	for _, name := range []string{"TLS13", "RFC8998-GCM", "RFC8998-CCM", "NTLS"} {
		t.Run(name, func(t *testing.T) {
			sc, root := testChainIdentity(t, false)
			cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "leaf.example", RequestOCSP: true}
			switch name {
			case "TLS13":
				sc.MinVersion = TLS1_3Version
				cc.MinVersion = TLS1_3Version
			case "NTLS":
				sc, root = testNTLSIdentity(t, "ntls.example")
				cc = &Config{NTLS: true, Verification: VerifyStrict, RootCAs: []*x509.Certificate{root}, VerificationName: "ntls.example", RequestOCSP: true}
			default:
				sc = rfc8998Identity(t)
				suite := "TLS_SM4_GCM_SM3"
				if name == "RFC8998-CCM" {
					suite = "TLS_SM4_CCM_SM3"
				}
				sc.CipherSuites = []string{suite}
				cc = &Config{RFC8998: true, CipherSuites: []string{suite}, Verification: VerifyStrict, RootCAs: []*x509.Certificate{sc.Cert}, VerificationName: "rfc8998.example", RequestOCSP: true}
			}
			sc.OCSPStaple = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
			c, _, ce, se := handshakePair(t, sc, cc)
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			state := c.ConnectionState()
			if name != "NTLS" && (!state.OCSPStapled || !bytes.Equal(state.OCSPResponse, sc.OCSPStaple)) {
				t.Fatal("configured staple did not arrive")
			}
			if name == "NTLS" {
				t.Logf("single NTLS staple received=%t", state.OCSPStapled)
				cc.OCSPPolicy = OCSPRequire
				_, _, ce, _ := handshakePair(t, sc, cc)
				if ce == nil {
					t.Fatal("NTLS without dual-certificate coverage was accepted")
				}
			}
		})
	}
}
