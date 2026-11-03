package keystore

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/blue-cloud-net/tongsuo-go/asym"
	"github.com/blue-cloud-net/tongsuo-go/meta"
	"github.com/blue-cloud-net/tongsuo-go/pkcs/pkcs12"
)

func openKeyURI(uri string) (io.ReadCloser, error) {
	if uri == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	if strings.Contains(uri, "://") {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("keystore: only local file URIs are supported")
		}
		uri = u.Path
	}
	f, err := os.Open(uri)
	if err != nil {
		return nil, fmt.Errorf("keystore: open: %w", err)
	}
	return f, nil
}
func loadKeysURI(uri string, pass *meta.Passphrase) ([]asym.Key, error) {
	r, err := openKeyURI(uri)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return LoadAllFromReader(r, pass)
}
func oneLoadedKey(keys []asym.Key, err error) (asym.Key, error) {
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		for _, k := range keys {
			asym.Close(k)
		}
		return nil, fmt.Errorf("keystore: expected one key, got %d; use LoadAll", len(keys))
	}
	return keys[0], nil
}

// Load 从本地路径、file URI 或 "-"（stdin）加载一个密钥；多对象返回错误。
// 支持 PEM、DER 和 PKCS#12；返回密钥须 asym.Close；调用方负责清零源缓冲。
//
// Load loads one key from a local path, file URI or "-" (stdin); multiple keys return an error.
// It accepts PEM, DER and PKCS#12. Call asym.Close on the key and wipe source buffers.
func Load(uri string) (asym.Key, error) { return oneLoadedKey(loadKeysURI(uri, nil)) }

// LoadAll 加载本地来源的全部密钥；调用方负责对每个密钥调用 asym.Close。
//
// LoadAll loads every key from a local source; callers must call asym.Close on each key.
func LoadAll(uri string) ([]asym.Key, error) { return loadKeysURI(uri, nil) }

// LoadWithPassphrase 使用指定口令加载一个密钥；支持空口令加密容器。
// 调用方负责 asym.Close 与源口令/密钥缓冲清零。
//
// LoadWithPassphrase loads one key using the supplied password, including encrypted containers with empty passwords.
// Callers must call asym.Close and wipe source password/key buffers.
func LoadWithPassphrase(uri string, pass *meta.Passphrase) (asym.Key, error) {
	return oneLoadedKey(loadKeysURI(uri, pass))
}

// LoadFromReader 从 reader 自动识别并加载一个密钥，不关闭 reader；密钥须 asym.Close。
//
// LoadFromReader detects and loads one key without closing the reader; call asym.Close on the key.
func LoadFromReader(r io.Reader) (asym.Key, error) { return oneLoadedKey(LoadAllFromReader(r, nil)) }

// LoadAllFromReader 自动识别 PEM 多对象、PKCS#8/PKCS#1/SEC1/SPKI DER 或 PKCS#12。
// PEM 中的证书与 CRL 被忽略；不支持的块或畸形输入返回错误且释放已解析密钥。
// 不关闭 reader；调用方负责 asym.Close 以及输入和口令缓冲清零。
//
// LoadAllFromReader detects multiple PEM objects, PKCS#8/PKCS#1/SEC1/SPKI DER or PKCS#12.
// Certificates and CRLs in PEM are ignored; unsupported blocks or malformed input return errors and release parsed keys.
// It does not close the reader; callers must call asym.Close and wipe input/password buffers.
func LoadAllFromReader(r io.Reader, pass *meta.Passphrase) (keys []asym.Key, retErr error) {
	if r == nil {
		return nil, fmt.Errorf("keystore: nil reader")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("keystore: read: %w", err)
	}
	password := string(pass.Bytes())
	defer func() {
		if retErr != nil {
			for _, k := range keys {
				asym.Close(k)
			}
			keys = nil
		}
	}()
	if bytes.Contains(data, []byte("-----BEGIN")) {
		rest := data
		for len(bytes.TrimSpace(rest)) > 0 {
			b, tail := pem.Decode(rest)
			if b == nil {
				return keys, fmt.Errorf("keystore: malformed PEM")
			}
			rest = tail
			encoded := pem.EncodeToMemory(b)
			var k asym.Key
			switch b.Type {
			case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
				if len(b.Headers) > 0 {
					k, err = asym.LoadEncryptedPrivateKeyPEM(encoded, password)
				} else {
					k, err = asym.LoadPrivateKeyPEM(encoded)
				}
			case "ENCRYPTED PRIVATE KEY":
				k, err = asym.LoadEncryptedPrivateKeyPEM(encoded, password)
			case "PUBLIC KEY":
				k, err = asym.LoadPublicKeyPEM(encoded)
			case "RSA PUBLIC KEY":
				k, err = asym.LoadRSAPublicKeyPKCS1PEM(encoded)
			case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CRL":
				continue
			default:
				return keys, fmt.Errorf("keystore: unsupported PEM type %q", b.Type)
			}
			if err != nil {
				return keys, err
			}
			keys = append(keys, k)
		}
	} else {
		// Relabel DER through PEM so all native key decoders stay in asym.
		for _, typ := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PUBLIC KEY", "RSA PUBLIC KEY", "ENCRYPTED PRIVATE KEY"} {
			encoded := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data})
			var k asym.Key
			switch typ {
			case "PUBLIC KEY":
				k, err = asym.LoadPublicKeyPEM(encoded)
			case "RSA PUBLIC KEY":
				k, err = asym.LoadRSAPublicKeyPKCS1PEM(encoded)
			case "ENCRYPTED PRIVATE KEY":
				k, err = asym.LoadEncryptedPrivateKeyPEM(encoded, password)
			default:
				k, err = asym.LoadPrivateKeyPEM(encoded)
			}
			if err == nil {
				return []asym.Key{k}, nil
			}
		}
		bundle, e := pkcs12.Parse(data, password)
		if e != nil {
			return nil, fmt.Errorf("keystore: unrecognized or encrypted key container: %w", e)
		}
		if bundle.Certificate != nil {
			bundle.Certificate.Close()
		}
		for _, c := range bundle.CACerts {
			c.Close()
		}
		if bundle.PrivateKey != nil {
			keys = append(keys, bundle.PrivateKey)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("keystore: no keys found")
	}
	return keys, nil
}
