// Package main 演示可连接指定地址的 TLS/NTLS 握手客户端和混合协议服务端。
//
// Package main demonstrates a TLS/NTLS handshake client and a mixed-protocol server.
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/tls"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	mode := flag.String("mode", "client", "client or server")
	protocol := flag.String("protocol", "tls", "tls, ntls, or mixed (server only)")
	addr := flag.String("addr", "127.0.0.1:4433", "remote or listening TCP address")
	verify := flag.String("verify", "report", "none, report, or strict")
	ca := flag.String("ca", "", "trusted CA PEM bundle")
	cert := flag.String("cert", "", "TLS leaf and intermediate PEM bundle")
	key := flag.String("key", "", "TLS private key PEM")
	signCert := flag.String("sign-cert", "", "NTLS signing leaf and intermediate PEM bundle")
	signKey := flag.String("sign-key", "", "NTLS signing private key PEM")
	encCert := flag.String("enc-cert", "", "NTLS encryption leaf and intermediate PEM bundle")
	encKey := flag.String("enc-key", "", "NTLS encryption private key PEM")
	sni := flag.String("servername", "", "client SNI")
	verifyName := flag.String("verify-name", "", "independent expected DNS name or IP")
	noSNI := flag.Bool("no-sni", false, "do not send SNI")
	alpn := flag.String("alpn", "", "comma-separated ALPN protocols")
	ciphers := flag.String("ciphers", "", "comma-separated exact cipher suite names")
	minVersion := flag.String("min-version", "", "minimum version: tls1.0, tls1.1, tls1.2, tls1.3, ntls1.1")
	maxVersion := flag.String("max-version", "", "maximum version: tls1.0, tls1.1, tls1.2, tls1.3, ntls1.1")
	dhParameters := flag.String("dh-params", "", "DH parameter PEM file")
	groups := flag.String("groups", "", "comma-separated named groups")
	signatures := flag.String("sigalgs", "", "comma-separated signature algorithms")
	clientAuth := flag.String("client-auth", "none", "server: none, request, or require")
	timeout := flag.Duration("timeout", 5*time.Second, "handshake and I/O timeout")
	message := flag.String("message", "", "client payload; empty performs only a handshake")
	response := flag.String("response", "echo", "server: echo or http")
	once := flag.Bool("once", false, "server: accept one connection and exit")
	flag.Parse()
	if *mode != "client" && *mode != "server" {
		return errors.New("mode must be client or server")
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if *response != "echo" && *response != "http" {
		return errors.New("response must be echo or http")
	}
	cfg := &tls.Config{ServerName: *sni, VerificationName: *verifyName, DisableSNI: *noSNI, NextProtos: split(*alpn), CipherSuites: split(*ciphers), StrictConfig: true, CurvePreferences: split(*groups), SignatureAlgorithms: split(*signatures)}
	switch *protocol {
	case "tls":
		cfg.Protocol = tls.ProtocolTLS
	case "ntls":
		cfg.Protocol = tls.ProtocolNTLS
	case "mixed":
		cfg.Protocol = tls.ProtocolMixed
	default:
		return errors.New("protocol must be tls, ntls or mixed")
	}
	switch *verify {
	case "none":
		cfg.Verification = tls.VerifyNone
	case "report":
		cfg.Verification = tls.VerifyReport
	case "strict":
		cfg.Verification = tls.VerifyStrict
	default:
		return errors.New("verify must be none, report or strict")
	}
	switch *clientAuth {
	case "none":
		cfg.ClientAuth = tls.NoClientCert
	case "request":
		cfg.ClientAuth = tls.RequestClientCert
	case "require":
		cfg.ClientAuth = tls.RequireAnyClientCert
	default:
		return errors.New("client-auth must be none, request or require")
	}
	versions := map[string]uint16{"": 0, "tls1.0": tls.TLS1Version, "tls1.1": tls.TLS1_1Version, "tls1.2": tls.TLS1_2Version, "tls1.3": tls.TLS1_3Version, "ntls1.1": tls.NTLSVersion}
	var ok bool
	if cfg.MinVersion, ok = versions[*minVersion]; !ok {
		return errors.New("invalid min-version")
	}
	if cfg.MaxVersion, ok = versions[*maxVersion]; !ok {
		return errors.New("invalid max-version")
	}
	if *dhParameters != "" {
		data, err := os.ReadFile(*dhParameters)
		if err != nil {
			return err
		}
		cfg.DHParameters = data
	}
	var ownedKeys []asym.PrivateKey
	var owned []*x509.Certificate
	defer func() {
		for _, key := range ownedKeys {
			_ = asym.Close(key)
		}
		for _, cert := range owned {
			_ = cert.Close()
		}
	}()
	loadBundle := func(path string) ([]*x509.Certificate, error) {
		if path == "" {
			return nil, nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var certs []*x509.Certificate
		for len(strings.TrimSpace(string(data))) > 0 {
			block, rest := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("invalid certificate bundle %s", path)
			}
			cert, err := x509.LoadCertificateDER(block.Bytes)
			if err != nil {
				return nil, err
			}
			owned = append(owned, cert)
			certs = append(certs, cert)
			data = rest
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("empty certificate bundle %s", path)
		}
		return certs, nil
	}
	loadCredential := func(certPath, keyPath string) (*tls.Certificate, error) {
		if certPath == "" && keyPath == "" {
			return nil, nil
		}
		if certPath == "" || keyPath == "" {
			return nil, errors.New("both certificate and key paths are required")
		}
		certs, err := loadBundle(certPath)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		private, err := asym.LoadPrivateKeyPEM(data)
		clear(data)
		if err != nil {
			return nil, err
		}
		ownedKeys = append(ownedKeys, private)
		return &tls.Certificate{Leaf: certs[0], PrivateKey: private, Chain: certs[1:]}, nil
	}
	roots, err := loadBundle(*ca)
	if err != nil {
		return err
	}
	cfg.RootCAs = roots
	cfg.ClientCAs = roots
	for i, pair := range [][2]string{{*cert, *key}, {*signCert, *signKey}, {*encCert, *encKey}} {
		identity, err := loadCredential(pair[0], pair[1])
		if err != nil {
			return err
		}
		if identity == nil {
			continue
		}
		switch i {
		case 0:
			cfg.Cert, cfg.Key, cfg.CertChain = identity.Leaf, identity.PrivateKey, identity.Chain
		case 1:
			cfg.SignCert, cfg.SignKey, cfg.SignChain = identity.Leaf, identity.PrivateKey, identity.Chain
		case 2:
			cfg.EncCert, cfg.EncKey, cfg.EncChain = identity.Leaf, identity.PrivateKey, identity.Chain
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if *mode == "client" {
		bounded, stop := context.WithTimeout(ctx, *timeout)
		defer stop()
		raw, err := (&net.Dialer{}).DialContext(bounded, "tcp", *addr)
		if err != nil {
			return err
		}
		conn, err := tls.Client(raw, cfg)
		if err != nil {
			_ = raw.Close()
			return err
		}
		defer conn.Close()
		err = conn.HandshakeContext(bounded)
		printState(conn)
		printHandshakeError(err)
		if err != nil {
			return err
		}
		if *message != "" {
			if err := conn.SetDeadline(time.Now().Add(*timeout)); err != nil {
				return err
			}
			if _, err := io.WriteString(conn, *message); err != nil {
				return err
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if n > 0 {
				fmt.Printf("response: %s\n", buf[:n])
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		}
		return nil
	}
	if cfg.Protocol != tls.ProtocolNTLS && cfg.Cert == nil {
		return errors.New("TLS server requires -cert and -key")
	}
	if cfg.Protocol != tls.ProtocolTLS && (cfg.SignCert == nil || cfg.EncCert == nil) {
		return errors.New("NTLS server requires signing and encryption credentials")
	}
	server, err := tls.NewServer(cfg)
	if err != nil {
		return err
	}
	defer server.Close()
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Printf("listening: %s\n", listener.Addr())
	go func() { <-ctx.Done(); _ = listener.Close() }()
	var workers sync.WaitGroup
	defer workers.Wait()
	serve := func(raw net.Conn) error {
		wrapped, err := server.Accept(raw)
		if err != nil {
			_ = raw.Close()
			return err
		}
		defer wrapped.Close()
		conn := wrapped.(*tls.Conn)
		bounded, stop := context.WithTimeout(ctx, *timeout)
		defer stop()
		err = conn.HandshakeContext(bounded)
		printState(conn)
		printHandshakeError(err)
		if err != nil {
			return err
		}
		if err := conn.SetDeadline(time.Now().Add(*timeout)); err != nil {
			return err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if *response == "http" {
			_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
		} else {
			_, err = conn.Write(buf[:n])
		}
		return err
	}
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if *once {
			return serve(raw)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := serve(raw); err != nil {
				log.Printf("connection: %v", err)
			}
		}()
	}
}

func split(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func printState(conn *tls.Conn) {
	state := conn.ConnectionState()
	fmt.Printf("peer=%s complete=%v version=0x%04x ntls=%v cipher=%s sni=%q alpn=%q group=%q peer-signature=%q verification=%d certificates=%d\n", conn.RemoteAddr(), state.HandshakeComplete, state.Version, state.NTLS, state.CipherName, state.ServerName, state.NegotiatedProtocol, state.NegotiatedGroup, state.PeerSignatureAlgorithm, state.Verification, len(state.PeerCertificates))
	for _, failure := range state.VerificationErrors {
		fmt.Printf("verify code=%d: %v\n", failure.Code, failure)
	}
}

func printHandshakeError(err error) {
	var failure *tls.HandshakeError
	if errors.As(err, &failure) {
		fmt.Printf("handshake error: ssl-code=%d verify-code=%d native-codes=%#x\n", failure.SSLCode, failure.VerifyCode, failure.NativeErrors)
	}
}
