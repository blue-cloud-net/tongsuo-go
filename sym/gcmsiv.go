package sym

import "crypto/cipher"

// NewAESGCMSIV 创建 AES-GCM-SIV AEAD，密钥为 16/24/32 字节，nonce 为 12 字节。
// 128/256 位遵循 RFC 8452；192 位是原生扩展。tag 为 16 字节，支持空消息。
// 调用方负责清零源密钥并为每条消息生成新 nonce；不可用返回 ErrUnsupported。
//
// NewAESGCMSIV creates AES-GCM-SIV with a 16/24/32-byte key and 12-byte nonce.
// The 128/256-bit variants follow RFC 8452; 192 bits is a native extension. Tags are 16 bytes; empty messages work.
// Callers must wipe source keys and generate a fresh nonce per message; unavailable support returns ErrUnsupported.
func NewAESGCMSIV(key []byte) (cipher.AEAD, error) {
	name, err := extendedAESName(key, "GCM-SIV")
	if err != nil {
		return nil, err
	}
	return NewAEAD(name, key)
}

// EncryptAESGCMSIV 使用 AES-GCM-SIV 加密并返回分离的密文与 16 字节 tag。
// nonce 必须为 12 字节；调用方负责清零源密钥并生成新 nonce，不可用返回 ErrUnsupported。
//
// EncryptAESGCMSIV encrypts with AES-GCM-SIV, returning ciphertext and a separate 16-byte tag.
// Nonce must be 12 bytes; callers must wipe source keys and use fresh nonces. Unavailable support returns ErrUnsupported.
func EncryptAESGCMSIV(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	name, err := extendedAESName(key, "GCM-SIV")
	if err != nil {
		return nil, nil, err
	}
	return EncryptAEAD(name, key, nonce, plaintext, aad)
}

// DecryptAESGCMSIV 校验 AES-GCM-SIV 的 tag 并解密，认证失败不返回明文。
// nonce 为 12 字节，tag 为 16 字节；不可用返回 ErrUnsupported。
//
// DecryptAESGCMSIV authenticates and decrypts AES-GCM-SIV, returning no plaintext on failure.
// Nonce is 12 bytes and tag is 16 bytes; unavailable support returns ErrUnsupported.
func DecryptAESGCMSIV(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	name, err := extendedAESName(key, "GCM-SIV")
	if err != nil {
		return nil, err
	}
	return DecryptAEAD(name, key, nonce, ciphertext, tag, aad)
}
