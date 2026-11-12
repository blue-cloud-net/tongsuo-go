package tls

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func normalizeRFC8998(cfg *Config) error {
	if !cfg.RFC8998 {
		return nil
	}
	if cfg.NTLS || (cfg.Protocol != ProtocolDefault && cfg.Protocol != ProtocolTLS) || cfg.SignCert != nil || cfg.SignKey != nil || cfg.EncCert != nil || cfg.EncKey != nil || len(cfg.SignChain)+len(cfg.EncChain) != 0 || cfg.GetNTLSCertificate != nil {
		return fmt.Errorf("tls: RFC 8998 requires TLS single signing credentials")
	}
	const version = 0x0304
	if cfg.MinVersion != 0 && cfg.MinVersion != version || cfg.MaxVersion != 0 && cfg.MaxVersion != version {
		return fmt.Errorf("tls: RFC 8998 requires TLS 1.3")
	}
	cfg.MinVersion, cfg.MaxVersion, cfg.StrictConfig = version, version, true
	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = []string{"TLS_SM4_GCM_SM3", "TLS_SM4_CCM_SM3"}
	}
	for _, name := range cfg.CipherSuites {
		if name != "TLS_SM4_GCM_SM3" && name != "TLS_SM4_CCM_SM3" {
			return fmt.Errorf("tls: RFC 8998 incompatible cipher %q", name)
		}
	}
	for _, entry := range []struct {
		list *[]string
		name string
	}{{&cfg.CurvePreferences, "curveSM2"}, {&cfg.SignatureAlgorithms, "sm2sig_sm3"}} {
		if len(*entry.list) == 0 {
			*entry.list = []string{entry.name}
		}
		for _, name := range *entry.list {
			if name != entry.name {
				return fmt.Errorf("tls: RFC 8998 incompatible parameter %q", name)
			}
		}
	}
	if cfg.Key != nil && cfg.Key.Algorithm() != asym.AlgSM2 {
		return fmt.Errorf("tls: RFC 8998 requires an SM2 private key")
	}
	if cfg.Cert != nil {
		return checkRFC8998Certificate(cfg.Cert)
	}
	return nil
}

func checkRFC8998Certificate(cert *x509.Certificate) error {
	if cert.SignatureAlgorithmOID() != "1.2.156.10197.1.501" {
		return fmt.Errorf("tls: RFC 8998 requires an SM2-SM3 certificate signature")
	}
	pub, err := cert.PublicKey()
	if err != nil {
		return fmt.Errorf("tls: RFC 8998 certificate public key: %w", err)
	}
	defer asym.Close(pub)
	if pub.Algorithm() != asym.AlgSM2 {
		return fmt.Errorf("tls: RFC 8998 requires an SM2 certificate public key")
	}
	usage := cert.KeyUsage()
	present := false
	for _, extension := range cert.Extensions() {
		if extension.OID == "2.5.29.15" {
			present = true
		}
	}
	if present {
		found := false
		for _, name := range usage {
			if name == "digitalSignature" {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("tls: RFC 8998 certificate key usage excludes digitalSignature")
		}
	}
	return nil
}

func checkRFC8998State(state ConnectionState) error {
	if state.Version != TLS1_3Version || state.CipherSuite != 0x00c6 && state.CipherSuite != 0x00c7 || state.NegotiatedGroup != "SM2" && state.NegotiatedGroup != "curveSM2" {
		return fmt.Errorf("tls: RFC 8998 negotiated parameters violate strict profile")
	}
	if len(state.PeerCertificates) > 0 {
		cert, err := x509.LoadCertificateDER(state.PeerCertificates[0])
		if err != nil {
			return err
		}
		defer cert.Close()
		return checkRFC8998Certificate(cert)
	}
	return nil
}
