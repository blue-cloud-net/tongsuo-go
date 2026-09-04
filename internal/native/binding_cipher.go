package native

/*
#include <openssl/evp.h>
*/
import "C"
import "unsafe"

// 加密方向常量（对应 EVP_CipherInit_ex 的 enc 参数）。
//
// Decrypt/Encrypt select the direction passed to the enc argument of
// EVP_CipherInit_ex (and friends).
const (
	Decrypt = 0
	Encrypt = 1
)

// EVP_sm4_ecb 返回 SM4-ECB 分组算法描述符（常量指针，不拥有所有权）。
// EVP_sm4_ecb returns the SM4-ECB cipher descriptor (static singleton, do not free).
func EVP_sm4_ecb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_ecb())
}

// EVP_sm4_cbc 返回 SM4-CBC 分组算法描述符。
// EVP_sm4_cbc returns the SM4-CBC cipher descriptor (static singleton, do not free).
func EVP_sm4_cbc() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_cbc())
}

// EVP_sm4_ctr 返回 SM4-CTR 分组算法描述符（流模式）。
// EVP_sm4_ctr returns the SM4-CTR cipher descriptor (stream mode, static singleton).
func EVP_sm4_ctr() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_ctr())
}

// EVP_sm4_ofb 返回 SM4-OFB 分组算法描述符（流模式）。
// EVP_sm4_ofb returns the SM4-OFB cipher descriptor (stream mode, static singleton).
func EVP_sm4_ofb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_ofb())
}

// EVP_sm4_cfb128 返回 SM4-CFB（128 位反馈）分组算法描述符（流模式）。
// EVP_sm4_cfb128 returns the SM4-CFB128 cipher descriptor (stream mode, static singleton).
func EVP_sm4_cfb128() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_cfb128())
}

// EVP_sm4_gcm 返回 SM4-GCM 认证加密算法描述符（AEAD）。
// EVP_sm4_gcm returns the SM4-GCM AEAD cipher descriptor (static singleton, do not free).
func EVP_sm4_gcm() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_gcm())
}

// EVP_aes_128_ecb 返回 AES-128-ECB 分组算法描述符。
// EVP_aes_128_ecb returns the AES-128-ECB cipher descriptor (static singleton).
func EVP_aes_128_ecb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_ecb())
}

// EVP_aes_128_cbc 返回 AES-128-CBC 分组算法描述符。
// EVP_aes_128_cbc returns the AES-128-CBC cipher descriptor (static singleton).
func EVP_aes_128_cbc() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_cbc())
}

// EVP_aes_128_ctr 返回 AES-128-CTR 分组算法描述符（流模式）。
// EVP_aes_128_ctr returns the AES-128-CTR cipher descriptor (stream mode, static singleton).
func EVP_aes_128_ctr() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_ctr())
}

// EVP_aes_128_gcm 返回 AES-128-GCM 认证加密算法描述符（AEAD）。
// EVP_aes_128_gcm returns the AES-128-GCM AEAD cipher descriptor (static singleton).
func EVP_aes_128_gcm() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_gcm())
}

// EVP_aes_256_ecb 返回 AES-256-ECB 分组算法描述符。
// EVP_aes_256_ecb returns the AES-256-ECB cipher descriptor (static singleton).
func EVP_aes_256_ecb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_ecb())
}

// EVP_aes_256_cbc 返回 AES-256-CBC 分组算法描述符。
// EVP_aes_256_cbc returns the AES-256-CBC cipher descriptor (static singleton).
func EVP_aes_256_cbc() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_cbc())
}

// EVP_aes_256_ctr 返回 AES-256-CTR 分组算法描述符（流模式）。
// EVP_aes_256_ctr returns the AES-256-CTR cipher descriptor (stream mode, static singleton).
func EVP_aes_256_ctr() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_ctr())
}

// EVP_aes_256_gcm 返回 AES-256-GCM 认证加密算法描述符（AEAD）。
// EVP_aes_256_gcm returns the AES-256-GCM AEAD cipher descriptor (static singleton).
func EVP_aes_256_gcm() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_gcm())
}

// EVP_CIPHER_CTX_ctrl 的 GCM 控制类型常量（对应 EVP_CTRL_AEAD_*）。
//
// CtrlGCMSetIVLen / CtrlGCMGetTag / CtrlGCMSetTag are the EVP_CTRL_AEAD_*
// control IDs forwarded to EVP_CIPHER_CTX_ctrl for GCM tag and IV handling.
const (
	CtrlGCMSetIVLen = 0x9  // 设置 IV/Nonce 长度
	CtrlGCMGetTag   = 0x10 // 加密后获取认证标签
	CtrlGCMSetTag   = 0x11 // 解密前设置认证标签
)

// EVP_CIPHER_CTX_ctrl 控制加密上下文（GCM tag 读写、IV 长度设置等）。
// EVP_CIPHER_CTX_ctrl adjusts cipher context settings (e.g. CtrlGCMSetIVLen,
// CtrlGCMGetTag, CtrlGCMSetTag). Returns true when OpenSSL reports success.
func EVP_CIPHER_CTX_ctrl(ctx unsafe.Pointer, ctrlType, arg int, ptr unsafe.Pointer) bool {
	return C.EVP_CIPHER_CTX_ctrl((*C.EVP_CIPHER_CTX)(ctx),
		C.int(ctrlType), C.int(arg), ptr) == 1
}

// EVP_UpdateAAD 处理附加认证数据（AAD）：输出指针传 NULL，仅参与认证不输出。
// 注意：GCM 加密上下文须用 EVP_EncryptUpdate 喂 AAD，解密上下文须用 EVP_DecryptUpdate。
// EVP_UpdateAAD feeds the Additional Authenticated Data into a GCM context;
// the output pointer is NULL and no plaintext/ciphertext is produced.
// For an encryption context it forwards to EVP_EncryptUpdate; for decryption
// it forwards to EVP_DecryptUpdate. An empty aad slice returns true.
func EVP_UpdateAAD(ctx unsafe.Pointer, aad []byte, enc bool) bool {
	if len(aad) == 0 {
		return true
	}
	var l C.int
	if enc {
		return C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx), nil, &l,
			(*C.uchar)(unsafe.Pointer(&aad[0])), C.int(len(aad))) == 1
	}
	return C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx), nil, &l,
		(*C.uchar)(unsafe.Pointer(&aad[0])), C.int(len(aad))) == 1
}

// EVP_CIPHER_get_block_size 返回分组算法块长度（字节）。
// EVP_CIPHER_get_block_size returns the cipher's block size in bytes
// (16 for AES / SM4, 8 for legacy ciphers).
func EVP_CIPHER_get_block_size(c unsafe.Pointer) int {
	return int(C.EVP_CIPHER_get_block_size((*C.EVP_CIPHER)(c)))
}

// EVP_CIPHER_get_key_length 返回分组算法密钥长度（字节）。
// EVP_CIPHER_get_key_length returns the cipher's expected key length in bytes
// (16 for AES-128, 32 for AES-256, 16 for SM4).
func EVP_CIPHER_get_key_length(c unsafe.Pointer) int {
	return int(C.EVP_CIPHER_get_key_length((*C.EVP_CIPHER)(c)))
}

// EVP_CIPHER_get_iv_length 返回分组算法 IV 长度（字节）。
// EVP_CIPHER_get_iv_length returns the cipher's IV length in bytes (0 for
// ECB, 16 for AES/SM4 CBC; GCM defaults to 12 unless CtrlGCMSetIVLen is used).
func EVP_CIPHER_get_iv_length(c unsafe.Pointer) int {
	return int(C.EVP_CIPHER_get_iv_length((*C.EVP_CIPHER)(c)))
}

// EVP_CIPHER_CTX_new 分配新的加密上下文。
// EVP_CIPHER_CTX_new allocates a new EVP_CIPHER_CTX. The caller owns the
// returned pointer and must release it with EVP_CIPHER_CTX_free.
func EVP_CIPHER_CTX_new() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_CIPHER_CTX_new())
}

// EVP_CIPHER_CTX_free 释放加密上下文。
// EVP_CIPHER_CTX_free releases ctx. Safe on NULL; the pointer must not be
// used after free.
func EVP_CIPHER_CTX_free(ctx unsafe.Pointer) {
	C.EVP_CIPHER_CTX_free((*C.EVP_CIPHER_CTX)(ctx))
}

// EVP_CIPHER_CTX_copy 将 src（含其算法/密钥/IV 状态）深拷贝到 dst。
// 拷贝成功后 dst 与 src 独立，可独立 Update/Final；失败时 dst 必须视为未定义。
// dst 必须是 EVP_CIPHER_CTX_new 分配但未初始化（或已初始化）的新上下文。
// EVP_CIPHER_CTX_copy deep-copies the state of src (cipher algorithm,
// key, IV, padding flag, etc.) into dst. After a successful copy,
// dst and src are fully independent and may be used concurrently for
// Update/Final operations. On failure dst's contents are undefined.
// dst must be allocated by EVP_CIPHER_CTX_new.
func EVP_CIPHER_CTX_copy(dst, src unsafe.Pointer) bool {
	return C.EVP_CIPHER_CTX_copy((*C.EVP_CIPHER_CTX)(dst), (*C.EVP_CIPHER_CTX)(src)) == 1
}

// EVP_CIPHER_CTX_set_padding 设置填充模式（1=PKCS7，0=无填充）。
// EVP_CIPHER_CTX_set_padding enables (PKCS#7) or disables padding: pad=1
// enables PKCS#7 padding, pad=0 disables it. Required to be 0 for stream
// modes and AEAD ciphers.
func EVP_CIPHER_CTX_set_padding(ctx unsafe.Pointer, pad int) bool {
	return C.EVP_CIPHER_CTX_set_padding((*C.EVP_CIPHER_CTX)(ctx), C.int(pad)) == 1
}

// EVP_CipherInit_ex 初始化加密/解密上下文。
// key/iv 可传空切片表示不设置（ECB 模式 iv 为空）。enc 取 Encrypt 或 Decrypt。
// EVP_CipherInit_ex sets up ctx with cipher, key, and iv for the direction
// enc (Encrypt or Decrypt). An empty key slice and/or empty iv slice means
// "do not update that argument" (use ECB with iv=nil). impl may be nil.
func EVP_CipherInit_ex(ctx, cipher, impl unsafe.Pointer, key, iv []byte, enc int) bool {
	var ok bool
	switch {
	case len(key) == 0 && len(iv) == 0:
		ok = C.EVP_CipherInit_ex((*C.EVP_CIPHER_CTX)(ctx), (*C.EVP_CIPHER)(cipher),
			(*C.ENGINE)(impl), nil, nil, C.int(enc)) == 1
	case len(key) == 0:
		ok = C.EVP_CipherInit_ex((*C.EVP_CIPHER_CTX)(ctx), (*C.EVP_CIPHER)(cipher),
			(*C.ENGINE)(impl), nil, (*C.uchar)(unsafe.Pointer(&iv[0])), C.int(enc)) == 1
	case len(iv) == 0:
		ok = C.EVP_CipherInit_ex((*C.EVP_CIPHER_CTX)(ctx), (*C.EVP_CIPHER)(cipher),
			(*C.ENGINE)(impl), (*C.uchar)(unsafe.Pointer(&key[0])), nil, C.int(enc)) == 1
	default:
		ok = C.EVP_CipherInit_ex((*C.EVP_CIPHER_CTX)(ctx), (*C.EVP_CIPHER)(cipher),
			(*C.ENGINE)(impl), (*C.uchar)(unsafe.Pointer(&key[0])),
			(*C.uchar)(unsafe.Pointer(&iv[0])), C.int(enc)) == 1
	}
	return ok
}

// EVP_EncryptUpdate 加密数据，输出写入 out，实际长度通过 outl 返回。
// EVP_EncryptUpdate processes in and writes ciphertext into out. The number
// of bytes written is stored in *outl (if non-nil). Returns true on success.
func EVP_EncryptUpdate(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	return cipherUpdate(ctx, out, in, outl, true)
}

// EVP_DecryptUpdate 解密数据，输出写入 out，实际长度通过 outl 返回。
// EVP_DecryptUpdate processes in and writes plaintext into out. The number
// of bytes written is stored in *outl (if non-nil). Returns true on success.
func EVP_DecryptUpdate(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	return cipherUpdate(ctx, out, in, outl, false)
}

func cipherUpdate(ctx unsafe.Pointer, out, in []byte, outl *int, enc bool) bool {
	var l C.int
	var ok bool
	if len(in) == 0 || len(out) == 0 {
		if enc {
			ok = C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx), nil, &l, nil, 0) == 1
		} else {
			ok = C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx), nil, &l, nil, 0) == 1
		}
	} else if enc {
		ok = C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in))) == 1
	} else {
		ok = C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in))) == 1
	}
	if outl != nil {
		*outl = int(l)
	}
	return ok
}

// EVP_EncryptFinal_ex 结束加密，输出剩余块（含填充），长度通过 outl 返回。
// EVP_EncryptFinal_ex flushes the encryption pipeline, writing the final
// block (including PKCS#7 padding when enabled) into out. The number of
// bytes written is stored in *outl (if non-nil).
func EVP_EncryptFinal_ex(ctx unsafe.Pointer, out []byte, outl *int) bool {
	return cipherFinal(ctx, out, outl, true)
}

// EVP_DecryptFinal_ex 结束解密（校验填充），长度通过 outl 返回。
// EVP_DecryptFinal_ex flushes the decryption pipeline and verifies padding.
// The number of plaintext bytes written into out is stored in *outl.
// Returns false when padding validation fails.
func EVP_DecryptFinal_ex(ctx unsafe.Pointer, out []byte, outl *int) bool {
	return cipherFinal(ctx, out, outl, false)
}

func cipherFinal(ctx unsafe.Pointer, out []byte, outl *int, enc bool) bool {
	var l C.int
	var ok bool
	if len(out) == 0 {
		if enc {
			ok = C.EVP_EncryptFinal_ex((*C.EVP_CIPHER_CTX)(ctx), nil, &l) == 1
		} else {
			ok = C.EVP_DecryptFinal_ex((*C.EVP_CIPHER_CTX)(ctx), nil, &l) == 1
		}
	} else if enc {
		ok = C.EVP_EncryptFinal_ex((*C.EVP_CIPHER_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l) == 1
	} else {
		ok = C.EVP_DecryptFinal_ex((*C.EVP_CIPHER_CTX)(ctx),
			(*C.uchar)(unsafe.Pointer(&out[0])), &l) == 1
	}
	if outl != nil {
		*outl = int(l)
	}
	return ok
}
