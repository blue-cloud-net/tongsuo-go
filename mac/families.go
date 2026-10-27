package mac

// CMAC 按底层分组算法计算 CMAC 标签。
// cipherName 取 "SM4"、"AES-128"、"AES-192"、"AES-256"（也可直接给
// "SM4-CBC" / "AES-128-CBC" 等完整名）；标签长度等于分组长度。
// 未知算法名返回 ErrUnknownAlgorithm；铜锁侧失败返回包装了 OpError 的错误。
//
// CMAC computes a CMAC tag under the given block cipher.
//
// cipherName accepts "SM4", "AES-128", "AES-192" or "AES-256" (the
// full names such as "SM4-CBC" / "AES-128-CBC" are accepted too); the
// tag length equals the cipher block length. An unknown algorithm name
// returns ErrUnknownAlgorithm; a Tongsuo-side failure returns an error
// wrapping an OpError.
func CMAC(cipherName string, key, data []byte) ([]byte, error) {
	return Sum("CMAC", key, data, &Options{Cipher: cipherName})
}

// GMAC 按底层 GCM 分组算法计算 GMAC 标签。
// cipherName 取 "SM4"、"AES-128"、"AES-192"、"AES-256"（也可直接给
// "SM4-GCM" 等完整名）；iv 是 GCM 的 nonce，必须与加密侧一致且不可复用。
//
// aad 会先于 data 送入（provider 的 GMAC 把全部输入都当作 AAD 处理），
// 因此结果等价于对 "aad || data" 计算的 GCM 标签。
//
// GMAC computes a GMAC tag under the given GCM-mode block cipher.
//
// cipherName accepts "SM4", "AES-128", "AES-192" or "AES-256" (the full
// names such as "SM4-GCM" are accepted too); iv is the GCM nonce, which
// MUST match the encrypting side and MUST NOT be reused.
//
// aad is fed before data (the provider's GMAC treats all input as AAD),
// so the result equals the GCM tag over "aad || data".
func GMAC(cipherName string, key, iv, aad, data []byte) ([]byte, error) {
	return Sum("GMAC", key, data, &Options{
		Cipher: cipherName,
		IV:     iv,
		AAD:    aad,
	})
}

// KMAC128 计算 KMAC-128 标签（NIST SP 800-185）。
// outLen 是输出字节数（必须大于 0）；custom 是 customization 串（可空）。
//
// KMAC128 computes a KMAC-128 tag (NIST SP 800-185). outLen is the
// output size in bytes (it must be greater than zero); custom is the
// customization string (it may be empty).
func KMAC128(key, data, custom []byte, outLen int) ([]byte, error) {
	return Sum("KMAC-128", key, data, &Options{
		Custom:    custom,
		OutputLen: outLen,
	})
}

// KMAC256 计算 KMAC-256 标签（NIST SP 800-185）。
// outLen 是输出字节数（必须大于 0）；custom 是 customization 串（可空）。
//
// KMAC256 computes a KMAC-256 tag (NIST SP 800-185). outLen is the
// output size in bytes (it must be greater than zero); custom is the
// customization string (it may be empty).
func KMAC256(key, data, custom []byte, outLen int) ([]byte, error) {
	return Sum("KMAC-256", key, data, &Options{
		Custom:    custom,
		OutputLen: outLen,
	})
}

// SipHash 计算 SipHash 标签。
// 密钥必须为 16 字节；默认输出长度为 16 字节（铜锁 provider 的默认值），
// 可用 Options.OutputLen 调为 8..16 字节。
//
// SipHash computes a SipHash tag. The key MUST be 16 bytes long; the
// default output is 16 bytes (the Tongsuo provider default), and
// Options.OutputLen may lower it to 8..16 bytes.
func SipHash(key, data []byte) ([]byte, error) {
	return Sum("SIPHASH", key, data, nil)
}

// Poly1305 计算 Poly1305 标签（RFC 8439）。
// 密钥必须为 32 字节；输出长度为 16 字节。
//
// Poly1305 computes a Poly1305 tag (RFC 8439). The key MUST be 32 bytes
// long; the output is 16 bytes.
func Poly1305(key, data []byte) ([]byte, error) {
	return Sum("POLY1305", key, data, nil)
}

// EIA3 计算铜锁独有的 EIA3 标签。
// key 必须是 16 字节（ZUC 密钥）；count 是 5 字节的计数器（IV）。
// 输出长度为 4 字节。
//
// EIA3 computes the Tongsuo-specific EIA3 tag. key MUST be 16 bytes
// long (the ZUC key); count is the 5-byte counter (IV). The output is 4
// bytes.
func EIA3(key, count, data []byte) ([]byte, error) {
	return Sum("EIA3", key, data, &Options{IV: count})
}
