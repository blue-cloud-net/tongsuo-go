package tls

import (
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestPQCGroups 验证后量子组的实际协商和应用数据传输。
//
// TestPQCGroups verifies negotiation and application traffic for post-quantum groups.
func TestPQCGroups(t *testing.T) {
	for _, group := range []string{
		"MLKEM512", "MLKEM768", "MLKEM1024", "X25519MLKEM768",
		"SecP256r1MLKEM768", "SecP384r1MLKEM1024", "curveSM2MLKEM768",
	} {
		t.Run(group, func(t *testing.T) {
			sc := testServerConfig(t)
			sc.MinVersion = TLS1_3Version
			sc.CurvePreferences = []string{group}
			available := slices.Contains(meta.TLSGroups(), group)
			if !available {
				if ctx, err := newContext(sc, false); err == nil {
					_ = ctx.Close()
					t.Fatalf("unlisted group was accepted: %s", group)
				}
				return
			}
			cc := &Config{MinVersion: TLS1_3Version, Verification: VerifyNone, CurvePreferences: []string{group}}
			c, s, ce, se := handshakePair(t, sc, cc)
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			for _, conn := range []*Conn{c, s} {
				state := conn.ConnectionState()
				if state.NegotiatedGroup != group || state.Version != TLS1_3Version {
					t.Fatalf("version=%x group=%q", state.Version, state.NegotiatedGroup)
				}
			}
			const message = "PQC TLS"
			if _, err := c.Write([]byte(message)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(message))
			if _, err := io.ReadFull(s, got); err != nil || string(got) != message {
				t.Fatalf("application data %q: %v", got, err)
			}
		})
	}
}

// TestPQCGroupMismatch 验证没有共同的密钥交换组时握手失败。
//
// TestPQCGroupMismatch verifies that handshaking fails without a common key-exchange group.
func TestPQCGroupMismatch(t *testing.T) {
	if !slices.Contains(meta.TLSGroups(), "X25519MLKEM768") {
		return
	}
	sc := testServerConfig(t)
	sc.MinVersion = TLS1_3Version
	sc.CurvePreferences = []string{"X25519MLKEM768"}
	cc := &Config{MinVersion: TLS1_3Version, Verification: VerifyNone, CurvePreferences: []string{"P-256"}}
	_, _, ce, se := handshakePair(t, sc, cc)
	if ce == nil || se == nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
}

func mldsaIdentity(t *testing.T, alg asym.Algorithm, serial int64) (*x509.Certificate, asym.PrivateKey) {
	t.Helper()
	key, err := asym.GenerateKey(alg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = asym.Close(key) })
	now := time.Now()
	cert, err := x509.CreateSelfSigned(x509.NewName().Add("CN", "pqc.example"), serial,
		now.Add(-time.Hour), now.Add(time.Hour), key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cert.Close() })
	return cert, key
}

// TestPQCAuthentication 验证 ML-DSA 证书认证及双向认证。
//
// TestPQCAuthentication verifies server and mutual authentication with ML-DSA certificates.
func TestPQCAuthentication(t *testing.T) {
	for index, alg := range []asym.Algorithm{asym.AlgMLDSA44, asym.AlgMLDSA65, asym.AlgMLDSA87} {
		if !asym.PQCAvailable(alg) {
			continue
		}
		for _, mutual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mutual=%t", alg, mutual), func(t *testing.T) {
				scheme := []string{"mldsa44", "mldsa65", "mldsa87"}[index]
				cert, key := mldsaIdentity(t, alg, 1)
				sc := &Config{Cert: cert, Key: key, MinVersion: TLS1_3Version, SignatureAlgorithms: []string{scheme}}
				cc := &Config{MinVersion: TLS1_3Version, Verification: VerifyStrict, VerificationName: "pqc.example",
					RootCAs: []*x509.Certificate{cert}, SignatureAlgorithms: []string{scheme}}
				if mutual {
					cc.Cert, cc.Key = mldsaIdentity(t, alg, 2)
					sc.ClientAuth = RequireAndVerifyClientCert
					sc.ClientCAs = []*x509.Certificate{cc.Cert}
					sc.Verification = VerifyStrict
				}
				c, s, ce, se := handshakePair(t, sc, cc)
				if ce != nil || se != nil {
					t.Fatalf("client=%v server=%v", ce, se)
				}
				if c.ConnectionState().Verification != VerificationPassed ||
					(mutual && s.ConnectionState().Verification != VerificationPassed) {
					t.Fatal("certificate verification failed")
				}
			})
		}
	}
}
