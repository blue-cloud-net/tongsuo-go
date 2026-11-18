package tls

import (
	"errors"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// OCSPPolicy 控制客户端如何验证装订响应。
//
// OCSPPolicy controls client validation of stapled responses.
type OCSPPolicy uint8

const (
	// OCSPUnchecked 不验证装订响应。
	//
	// OCSPUnchecked leaves staples unchecked.
	OCSPUnchecked OCSPPolicy = iota
	// OCSPVerifyIfPresent 验证收到的响应，允许响应缺失。
	//
	// OCSPVerifyIfPresent verifies a received response and permits absence.
	OCSPVerifyIfPresent
	// OCSPRequire 要求有效的装订响应或已重新验证的会话响应。
	//
	// OCSPRequire requires a valid staple or a revalidated session response.
	OCSPRequire
)

func verifyStaple(der []byte, chain [][]byte, now time.Time) error {
	if len(chain) < 2 {
		return errors.New("tls: OCSP requires a verified issuer chain")
	}
	certs, err := loadOCSPChain(chain)
	if err != nil {
		return err
	}
	defer closeOCSPChain(certs)
	return verifyStapleWithChain(der, certs, now)
}

func loadOCSPChain(chain [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(chain))
	for _, data := range chain {
		cert, err := x509.LoadCertificateDER(data)
		if err != nil {
			closeOCSPChain(certs)
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func closeOCSPChain(certs []*x509.Certificate) {
	for _, cert := range certs {
		_ = cert.Close()
	}
}

func verifyStapleWithChain(der []byte, certs []*x509.Certificate, now time.Time) error {
	if len(certs) < 2 {
		return errors.New("tls: OCSP requires a verified issuer chain")
	}
	resp, err := x509.ParseOCSPResponse(der, certs[0], certs[1])
	if err != nil {
		return err
	}
	defer resp.Close()
	if resp.Status != 0 || resp.CertStatus != x509.OCSPGood {
		return errors.New("tls: OCSP status is not good")
	}
	if err := checkOCSPTime(resp, now); err != nil {
		return err
	}
	store := x509.NewStore()
	defer store.Close()
	if err := store.AddCert(certs[len(certs)-1]); err != nil {
		return err
	}
	return resp.Verify(store, certs[1:])
}

func checkOCSPTime(resp *x509.Response, now time.Time) error {
	const skew = 5 * time.Minute
	end := resp.NextUpdate
	if end.IsZero() {
		end = resp.ThisUpdate.Add(24 * time.Hour)
	}
	if resp.ThisUpdate.IsZero() || resp.ThisUpdate.After(now.Add(skew)) ||
		resp.ProducedAt.IsZero() || resp.ProducedAt.After(now.Add(skew)) ||
		end.Before(resp.ThisUpdate) || end.Before(now.Add(-skew)) {
		return errors.New("tls: OCSP response outside its validity interval")
	}
	return nil
}

// WithOCSPResponse 附加恢复时重新验证的响应副本。
//
// WithOCSPResponse attaches a copied response for revalidation on resumption.
func (s *SessionState) WithOCSPResponse(der []byte) (*SessionState, error) {
	if s == nil || len(der) == 0 || len(der) > 0xffffff {
		return nil, errors.New("tls: invalid session OCSP response")
	}
	copy := copySession(s)
	copy.ocsp = append([]byte(nil), der...)
	return copy, nil
}

func (c *Conn) verifyConnectionOCSP(state *ConnectionState, policy OCSPPolicy) error {
	if len(state.OCSPResponse) == 0 && state.SessionReused && c.resuming != nil && len(c.resuming.ocsp) > 0 {
		state.OCSPResponse = append([]byte(nil), c.resuming.ocsp...)
		state.OCSPFromSession = true
	}
	if len(state.OCSPResponse) == 0 && policy == OCSPVerifyIfPresent {
		return nil
	}
	state.OCSPVerification = VerificationFailed
	if state.NTLS {
		return errors.New("tls: OCSP cannot verify both NTLS certificates")
	}
	if len(state.OCSPResponse) == 0 {
		return errors.New("tls: required OCSP staple missing")
	}
	if state.Verification != VerificationPassed || len(state.VerifiedChains) == 0 {
		return errors.New("tls: OCSP requires a verified peer chain")
	}
	if err := verifyStaple(state.OCSPResponse, state.VerifiedChains[0], time.Now()); err != nil {
		return err
	}
	state.OCSPVerification = VerificationPassed
	return nil
}

func verifySessionStaple(cfg *Config, session *SessionState) error {
	chain := session.ocspChain
	if len(chain) == 0 {
		chain = session.peers
	}
	if len(chain) == 0 {
		return errors.New("tls: missing session certificate chain")
	}
	roots := x509.NewStore()
	defer roots.Close()
	if len(cfg.RootCAs) == 0 {
		if err := roots.SetDefaultPaths(); err != nil {
			return err
		}
	}
	for _, root := range cfg.RootCAs {
		if err := roots.AddCert(root); err != nil {
			return err
		}
	}
	certs, err := loadOCSPChain(chain)
	if err != nil {
		return err
	}
	defer closeOCSPChain(certs)
	verified, err := x509.ChainVerify(certs[0], roots, certs[1:])
	if err != nil {
		return err
	}
	defer closeOCSPChain(verified)
	return verifyStapleWithChain(session.ocsp, verified, time.Now())
}
