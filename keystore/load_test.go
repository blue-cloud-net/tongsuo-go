package keystore

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"github.com/blue-cloud-net/tongsuo-go/pkcs/pkcs12"
	"github.com/blue-cloud-net/tongsuo-go/x509"
)

// TestUnifiedKeyLoading 验证 PEM/DER、混合对象、PKCS#12、file URI 与错误清理。
//
// TestUnifiedKeyLoading checks PEM/DER, mixed objects, PKCS#12, file URIs and failure cleanup.
func TestUnifiedKeyLoading(t *testing.T) {
	priv, err := asym.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	defer asym.Close(priv)
	privatePEM, err := priv.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := priv.Public().MarshalPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pub1, err := asym.MarshalRSAPublicKeyPKCS1PEM(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.CreateCertificate(x509.NewName().Add("CN", "loader"), x509.NewName().Add("CN", "loader"), 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()
	certPEM, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	pass, err := meta.NewPassphrase("pass:secret")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := asym.MarshalPKCS8(priv, meta.FormatDER, &asym.PKCS8Options{Encrypt: true, Passphrase: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	p12, err := pkcs12.PackWithOptions(cert, priv, nil, &pkcs12.Options{WritePass: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{privatePEM, publicPEM, pub1, encrypted, p12} {
		keyPass := pass
		for _, blob := range [][]byte{data, func() []byte {
			b, _ := pem.Decode(data)
			if b != nil {
				return b.Bytes
			}
			return data
		}()} {
			keys, err := LoadAllFromReader(bytes.NewReader(blob), keyPass)
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 1 {
				t.Fatalf("keys=%d", len(keys))
			}
			if keys[0].Algorithm() != asym.AlgRSA {
				t.Fatal("wrong algorithm")
			}
			asym.Close(keys[0])
		}
	}
	multi := append(append(append([]byte(nil), certPEM...), privatePEM...), publicPEM...)
	keys, err := LoadAllFromReader(bytes.NewReader(multi), nil)
	if err != nil || len(keys) != 2 {
		t.Fatalf("mixed: %d %v", len(keys), err)
	}
	for _, k := range keys {
		asym.Close(k)
	}
	if _, err := LoadFromReader(bytes.NewReader(multi)); err == nil {
		t.Fatal("multiple keys accepted as one")
	}
	for _, data := range [][]byte{nil, []byte("bad"), certPEM, append(append([]byte(nil), privatePEM...), []byte("trailing garbage")...), append(append([]byte(nil), privatePEM...), pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN", Bytes: []byte{1}})...)} {
		if keys, err := LoadAllFromReader(bytes.NewReader(data), nil); err == nil || keys != nil {
			for _, k := range keys {
				asym.Close(k)
			}
			t.Fatalf("bad input accepted: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "key file.pem")
	if err = os.WriteFile(path, privatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{path, "file://" + path} {
		k, err := Load(uri)
		if err != nil {
			t.Fatal(err)
		}
		asym.Close(k)
	}
	if _, err := Load("https://example.invalid/key"); err == nil {
		t.Fatal("non-file URI accepted")
	}
	if err = os.WriteFile(path, p12, 0600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadWithPassphrase(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	asym.Close(k)
	if _, err := Load(path); err == nil {
		t.Fatal("encrypted container without password accepted")
	}
}
