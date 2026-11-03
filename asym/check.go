package asym

import "fmt"

// Check 校验私钥及密钥对的一致性；nil 或已关闭密钥返回错误。
//
// Check validates a private key and pair consistency; nil or closed keys return errors.
func Check(priv PrivateKey) error {
	if priv == nil {
		return fmt.Errorf("asym: nil private key")
	}
	return priv.corePKey().Check(false)
}

// PublicCheck 校验公钥参数；nil 或已关闭密钥返回错误。
//
// PublicCheck validates public-key parameters; nil or closed keys return errors.
func PublicCheck(pub PublicKey) error {
	if pub == nil {
		return fmt.Errorf("asym: nil public key")
	}
	return pub.corePKey().Check(true)
}
