package core

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/blue-cloud-net/tongsuo-go/internal/native"
)

func pkcs7CertStack(certs []*Certificate) (unsafe.Pointer, error) {
	stack := native.X509_sk_X509_new_null()
	if stack == nil {
		return nil, NewOpError("pkcs7: certificate stack", native.PopError())
	}
	for _, cert := range certs {
		if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
			native.X509_sk_X509_free(stack)
			return nil, fmt.Errorf("pkcs7: invalid certificate")
		}
		if !native.X509_sk_X509_push(stack, cert.handle.Ptr()) {
			native.X509_sk_X509_free(stack)
			return nil, NewOpError("pkcs7: push certificate", native.PopError())
		}
	}
	return stack, nil
}
func pkcs7Input(data []byte) (*MemBIO, error) {
	bio, err := NewMemBIO()
	if err != nil {
		return nil, err
	}
	if err = bio.Write(data); err != nil {
		bio.Close()
		return nil, err
	}
	return bio, nil
}
func pkcs7Bytes(bio *MemBIO) ([]byte, error) {
	if native.BIO_ctrl_pending(bio.bio) == 0 {
		return []byte{}, nil
	}
	return bio.Bytes()
}
func pkcs7Key(key *PKey, rsaOnly bool) error {
	if key == nil || key.handle == nil || key.handle.IsClosed() {
		return fmt.Errorf("pkcs7: invalid key")
	}
	alg := key.Algorithm()
	if alg != "RSA" && (rsaOnly || alg != "EC") {
		return fmt.Errorf("pkcs7: unsupported key algorithm %q", alg)
	}
	return nil
}

// SignPKCS7 签名并返回 DER；借用输入证书和密钥，失败释放全部临时资源。
//
// SignPKCS7 returns signed DER, borrowing certificate/key inputs and freeing all temporaries on failure.
func SignPKCS7(data []byte, cert *Certificate, key *PKey, extra []*Certificate, digest string, detached bool) ([]byte, error) {
	defer runtime.KeepAlive(cert)
	defer runtime.KeepAlive(key)
	defer runtime.KeepAlive(extra)
	if err := pkcs7Key(key, false); err != nil {
		return nil, err
	}
	if strings.ContainsRune(digest, 0) {
		return nil, fmt.Errorf("pkcs7: invalid digest")
	}
	if cert == nil || cert.handle == nil || cert.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs7: invalid certificate")
	}
	extras, err := pkcs7CertStack(extra)
	if err != nil {
		return nil, err
	}
	defer native.X509_sk_X509_free(extras)
	bio, err := pkcs7Input(data)
	if err != nil {
		return nil, err
	}
	defer bio.Close()
	ptr := native.X_PKCS7_sign(cert.handle.Ptr(), key.handle.Ptr(), extras, bio.bio, digest, detached)
	if ptr == nil {
		return nil, NewOpError("pkcs7: sign", native.PopError())
	}
	p := &PKCS7{handle: NewHandle(ptr, true, native.PKCS7_free)}
	defer p.Close()
	return p.MarshalDER()
}

// VerifySignatures 验证所有签名并复制签名者证书；信任校验由上层执行。
// 返回证书由调用方 Close，失败无内容与部分证书。
//
// VerifySignatures verifies all signatures and copies signer certificates; the API verifies trust.
// Callers Close returned certificates; failures return no content or partial certificates.
func (p *PKCS7) VerifySignatures(content []byte, extra []*Certificate) ([]byte, []*Certificate, error) {
	defer runtime.KeepAlive(p)
	defer runtime.KeepAlive(extra)
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return nil, nil, fmt.Errorf("pkcs7: closed")
	}
	stack, err := pkcs7CertStack(extra)
	if err != nil {
		return nil, nil, err
	}
	defer native.X509_sk_X509_free(stack)
	input, err := pkcs7Input(content)
	if err != nil {
		return nil, nil, err
	}
	defer input.Close()
	output, err := NewMemBIO()
	if err != nil {
		return nil, nil, err
	}
	defer output.Close()
	if !native.X_PKCS7_verify(p.handle.Ptr(), stack, input.bio, output.bio, content != nil) {
		return nil, nil, NewOpError("pkcs7: verify signatures", native.PopError())
	}
	signers := native.PKCS7_get0_signers(p.handle.Ptr(), stack)
	if signers == nil {
		return nil, nil, fmt.Errorf("pkcs7: no signers")
	}
	defer native.X509_sk_X509_free(signers)
	var result []*Certificate
	success := false
	defer func() {
		if !success {
			for _, c := range result {
				c.Close()
			}
		}
	}()
	for i := 0; i < native.X509_sk_X509_num(signers); i++ {
		ptr := native.X509_dup(native.X509_sk_X509_value(signers, i))
		if ptr == nil {
			return nil, nil, NewOpError("pkcs7: copy signer", native.PopError())
		}
		cert := &Certificate{handle: NewHandle(ptr, true, native.X509_free), signed: true}
		result = append(result, cert)
		pub, err := cert.PublicKey()
		if err != nil {
			return nil, nil, err
		}
		err = pkcs7Key(pub, false)
		pub.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	bytes, err := pkcs7Bytes(output)
	if err != nil {
		return nil, nil, err
	}
	success = true
	return bytes, result, nil
}

// EncryptPKCS7 加密到多个 RSA 接收者，返回 DER；参数与原生失败返回错误。
//
// EncryptPKCS7 encrypts to multiple RSA recipients and returns DER; invalid parameters or native failures return errors.
func EncryptPKCS7(data []byte, recipients []*Certificate, cipher string) ([]byte, error) {
	defer runtime.KeepAlive(recipients)
	if len(recipients) == 0 {
		return nil, fmt.Errorf("pkcs7: no recipients")
	}
	switch cipher {
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "DES-EDE3-CBC":
	default:
		return nil, fmt.Errorf("pkcs7: unsupported cipher %q", cipher)
	}
	stack, err := pkcs7CertStack(recipients)
	if err != nil {
		return nil, err
	}
	defer native.X509_sk_X509_free(stack)
	for _, c := range recipients {
		pub, err := c.PublicKey()
		if err != nil {
			return nil, err
		}
		err = pkcs7Key(pub, true)
		pub.Close()
		if err != nil {
			return nil, err
		}
	}
	input, err := pkcs7Input(data)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	ptr := native.X_PKCS7_encrypt(stack, input.bio, cipher)
	if ptr == nil {
		return nil, NewOpError("pkcs7: encrypt", native.PopError())
	}
	p := &PKCS7{handle: NewHandle(ptr, true, native.PKCS7_free)}
	defer p.Close()
	return p.MarshalDER()
}

// DecryptContent 解密 EnvelopedData；失败不返回部分明文。
//
// DecryptContent decrypts EnvelopedData without returning partial plaintext on failure.
func (p *PKCS7) DecryptContent(cert *Certificate, key *PKey) ([]byte, error) {
	defer runtime.KeepAlive(p)
	defer runtime.KeepAlive(cert)
	defer runtime.KeepAlive(key)
	if p == nil || p.handle == nil || p.handle.IsClosed() {
		return nil, fmt.Errorf("pkcs7: closed")
	}
	if err := pkcs7Key(key, true); err != nil {
		return nil, err
	}
	stack, err := pkcs7CertStack([]*Certificate{cert})
	if err != nil {
		return nil, err
	}
	defer native.X509_sk_X509_free(stack)
	out, err := NewMemBIO()
	if err != nil {
		return nil, err
	}
	defer out.Close()
	if !native.X_PKCS7_decrypt(p.handle.Ptr(), key.handle.Ptr(), cert.handle.Ptr(), out.bio) {
		return nil, NewOpError("pkcs7: decrypt", native.PopError())
	}
	return pkcs7Bytes(out)
}
