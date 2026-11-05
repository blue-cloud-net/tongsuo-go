package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func testChainIdentity(t testing.TB, expired bool) (*Config, *x509.Certificate) {
	t.Helper()
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	rootKey, interKey, leafKey := makeKey(), makeKey(), makeKey()
	template := func(serial int64, cn string, ca bool) *stdx509.Certificate {
		return &stdx509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageCertSign}
	}
	root := template(1, "root.example", true)
	inter := template(2, "intermediate.example", true)
	leaf := template(3, "leaf.example", false)
	leaf.KeyUsage = stdx509.KeyUsageDigitalSignature
	leaf.DNSNames = []string{"leaf.example", "*.wild.example"}
	leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	leaf.EmailAddresses = []string{"admin@leaf.example"}
	leaf.ExtKeyUsage = []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth, stdx509.ExtKeyUsageClientAuth}
	if expired {
		leaf.NotAfter = time.Now().Add(-time.Minute)
	}
	create := func(cert, parent *stdx509.Certificate, pub any, key any) *x509.Certificate {
		der, err := stdx509.CreateCertificate(crand.Reader, cert, parent, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		out, err := x509.LoadCertificateDER(der)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = out.Close() })
		return out
	}
	ca := create(root, root, &rootKey.PublicKey, rootKey)
	interCert := create(inter, root, &interKey.PublicKey, rootKey)
	leafCert := create(leaf, inter, &leafKey.PublicKey, interKey)
	der, err := stdx509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := asym.LoadPrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = asym.Close(key) })
	return &Config{Cert: leafCert, Key: key, CertChain: []*x509.Certificate{interCert}}, ca
}

// TestHandshakeChainAndNames 验证完整链、IP、邮箱和主机名 flags。
//
// TestHandshakeChainAndNames verifies complete chains, IPs, email and hostname flags.
func TestHandshakeChainAndNames(t *testing.T) {
	for _, version := range []uint16{TLS1_2Version, TLS1_3Version} {
		t.Run(map[uint16]string{TLS1_2Version: "TLS12", TLS1_3Version: "TLS13"}[version], func(t *testing.T) {
			sc, ca := testChainIdentity(t, false)
			sc.MinVersion = version
			sc.MaxVersion = version
			cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{ca}, HostnameOptions: HostnameOptions{Email: "admin@leaf.example"}}
			c, _, ce, se := handshakePair(t, sc, cc)
			if ce != nil || se != nil {
				t.Fatalf("client=%v server=%v", ce, se)
			}
			state := c.ConnectionState()
			if state.Version != version || len(state.PeerCertificates) != 2 || len(state.VerifiedChains) != 1 || len(state.VerifiedChains[0]) != 3 {
				t.Fatalf("chain state=%+v", state)
			}
			if err := c.CheckEmail("admin@leaf.example"); err != nil {
				t.Fatal(err)
			}
			if err := c.CheckEmail("other@leaf.example"); err == nil {
				t.Fatal("wrong email accepted")
			}
		})
	}
	for _, scenario := range []string{"missing-intermediate", "expired", "hostname", "email", "wildcard"} {
		t.Run(scenario, func(t *testing.T) {
			sc, ca := testChainIdentity(t, scenario == "expired")
			cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{ca}, VerificationName: "leaf.example"}
			switch scenario {
			case "missing-intermediate":
				sc.CertChain = nil
			case "hostname":
				cc.VerificationName = "other.example"
			case "email":
				cc.HostnameOptions.Email = "other@example.com"
			case "wildcard":
				cc.VerificationName = "one.wild.example"
				cc.HostnameOptions.Flags = HostnameNoWildcards
			}
			_, _, ce, _ := handshakePair(t, sc, cc)
			if ce == nil {
				t.Fatal("invalid chain/name accepted")
			}
			want := map[string]int{"missing-intermediate": x509.VerifyUnableToGetIssuerCertLocally, "expired": x509.VerifyCertHasExpired, "hostname": x509.VerifyHostnameMismatch, "email": x509.VerifyEmailMismatch, "wildcard": x509.VerifyHostnameMismatch}[scenario]
			var failure *HandshakeError
			if !errors.As(ce, &failure) || failure.VerifyCode != want || failure.SSLCode != SSLErrorSSL || len(failure.NativeErrors) == 0 {
				t.Fatalf("expected native verification code %d: %+v", want, ce)
			}
		})
	}
}

// TestHandshakeSNIReplacesVersionSignatureAndDH 验证完整 SNI 配置替换版本、签名和 DH 参数。
//
// TestHandshakeSNIReplacesVersionSignatureAndDH verifies full SNI selection replaces version, signature and DH settings.
func TestHandshakeSNIReplacesVersionSignatureAndDH(t *testing.T) {
	base, _ := testChainIdentity(t, false)
	base.MinVersion = TLS1_3Version
	base.SignatureAlgorithms = []string{"ecdsa_secp256r1_sha256"}
	private, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &stdx509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "dh.example"}, DNSNames: []string{"dh.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: stdx509.KeyUsageCertSign | stdx509.KeyUsageDigitalSignature, ExtKeyUsage: []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth}}
	der, err := stdx509.CreateCertificate(crand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.LoadCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()
	keyDER, err := stdx509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := asym.LoadPrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	defer asym.Close(key)
	// Public RFC 7919 ffdhe2048 parameters; no private material.
	const parameters = `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
`
	selected := &Config{Cert: cert, Key: key, MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version, CipherSuites: []string{"DHE-RSA-AES128-GCM-SHA256"}, StrictConfig: true, SignatureAlgorithms: []string{"rsa_pss_rsae_sha256"}, DHParameters: []byte(parameters)}
	base.GetConfigForClient = func(*ClientHelloInfo) (*Config, error) { return selected, nil }
	cc := &Config{Verification: VerifyStrict, RootCAs: []*x509.Certificate{cert}, VerificationName: "dh.example", MinVersion: TLS1_2Version, MaxVersion: TLS1_2Version, CipherSuites: selected.CipherSuites, StrictConfig: true, SignatureAlgorithms: selected.SignatureAlgorithms}
	c, _, ce, se := handshakePair(t, base, cc)
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	state := c.ConnectionState()
	if state.Version != TLS1_2Version || state.CipherName != "DHE-RSA-AES128-GCM-SHA256" || state.PeerSignatureAlgorithm == "" {
		t.Fatalf("state=%+v", state)
	}
}
