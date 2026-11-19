package asym

import "fmt"

func mlkemCiphertextSize(key Key) int {
	if key == nil {
		return 0
	}
	switch key.Algorithm() {
	case AlgMLKEM512:
		return 768
	case AlgMLKEM768:
		return 1088
	case AlgMLKEM1024:
		return 1568
	default:
		return 0
	}
}

// Encapsulate 使用 ML-KEM 公钥生成密文和 32 字节共享秘密。调用方负责清零秘密。
//
// Encapsulate generates a ciphertext and a 32-byte shared secret using an ML-KEM
// public key. The caller must wipe the shared secret.
func Encapsulate(pub PublicKey) (ciphertext, secret []byte, err error) {
	size := mlkemCiphertextSize(pub)
	if size == 0 {
		return nil, nil, fmt.Errorf("%w: expected ML-KEM public key", ErrInvalidKey)
	}
	return pub.corePKey().EncapsulateMLKEM(size)
}

// Decapsulate 使用 ML-KEM 私钥解封装，调用方负责清零返回的共享秘密。
// 错误长度返回错误。算法对等长无效密文按隐式拒绝返回替代秘密。
//
// Decapsulate uses an ML-KEM private key. The caller must wipe the returned shared secret.
// Incorrect lengths return an error. Implicit rejection yields a substitute secret for invalid
// ciphertext of the correct length.
func Decapsulate(priv PrivateKey, ciphertext []byte) ([]byte, error) {
	size := mlkemCiphertextSize(priv)
	if size == 0 {
		return nil, fmt.Errorf("%w: expected ML-KEM private key", ErrInvalidKey)
	}
	if len(ciphertext) != size {
		return nil, fmt.Errorf("asym: ML-KEM ciphertext length %d, expected %d", len(ciphertext), size)
	}
	return priv.corePKey().DecapsulateMLKEM(ciphertext)
}
