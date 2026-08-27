package native

/*
#include <openssl/evp.h>
*/
import "C"
import "unsafe"

// 加密方向常量（对应 EVP_CipherInit_ex 的 enc 参数）。
const (
	Decrypt = 0
	Encrypt = 1
)

// EVP_sm4_ecb 返回 SM4-ECB 分组算法描述符（常量指针，不拥有所有权）。
func EVP_sm4_ecb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_ecb())
}

// EVP_sm4_cbc 返回 SM4-CBC 分组算法描述符。
func EVP_sm4_cbc() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_cbc())
}

// EVP_sm4_ctr 返回 SM4-CTR 分组算法描述符（流模式）。
func EVP_sm4_ctr() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_ctr())
}

// EVP_sm4_ofb 返回 SM4-OFB 分组算法描述符（流模式）。
func EVP_sm4_ofb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_ofb())
}

// EVP_sm4_cfb128 返回 SM4-CFB（128 位反馈）分组算法描述符（流模式）。
func EVP_sm4_cfb128() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_cfb128())
}

// EVP_sm4_gcm 返回 SM4-GCM 认证加密算法描述符（AEAD）。
func EVP_sm4_gcm() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_sm4_gcm())
}

// EVP_aes_128_ecb 返回 AES-128-ECB 分组算法描述符。
func EVP_aes_128_ecb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_ecb())
}

// EVP_aes_128_cbc 返回 AES-128-CBC 分组算法描述符。
func EVP_aes_128_cbc() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_cbc())
}

// EVP_aes_128_ctr 返回 AES-128-CTR 分组算法描述符（流模式）。
func EVP_aes_128_ctr() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_ctr())
}

// EVP_aes_128_gcm 返回 AES-128-GCM 认证加密算法描述符（AEAD）。
func EVP_aes_128_gcm() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_128_gcm())
}

// EVP_aes_256_ecb 返回 AES-256-ECB 分组算法描述符。
func EVP_aes_256_ecb() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_ecb())
}

// EVP_aes_256_cbc 返回 AES-256-CBC 分组算法描述符。
func EVP_aes_256_cbc() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_cbc())
}

// EVP_aes_256_ctr 返回 AES-256-CTR 分组算法描述符（流模式）。
func EVP_aes_256_ctr() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_ctr())
}

// EVP_aes_256_gcm 返回 AES-256-GCM 认证加密算法描述符（AEAD）。
func EVP_aes_256_gcm() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_aes_256_gcm())
}

// EVP_CIPHER_CTX_ctrl 的 GCM 控制类型常量（对应 EVP_CTRL_AEAD_*）。
const (
	CtrlGCMSetIVLen = 0x9  // 设置 IV/Nonce 长度
	CtrlGCMGetTag   = 0x10 // 加密后获取认证标签
	CtrlGCMSetTag   = 0x11 // 解密前设置认证标签
)

// EVP_CIPHER_CTX_ctrl 控制加密上下文（GCM tag 读写、IV 长度设置等）。
func EVP_CIPHER_CTX_ctrl(ctx unsafe.Pointer, ctrlType, arg int, ptr unsafe.Pointer) bool {
	return C.EVP_CIPHER_CTX_ctrl((*C.EVP_CIPHER_CTX)(ctx),
		C.int(ctrlType), C.int(arg), ptr) == 1
}

// EVP_UpdateAAD 处理附加认证数据（AAD）：输出指针传 NULL，仅参与认证不输出。
// 注意：GCM 加密上下文须用 EVP_EncryptUpdate 喂 AAD，解密上下文须用 EVP_DecryptUpdate。
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
func EVP_CIPHER_get_block_size(c unsafe.Pointer) int {
	return int(C.EVP_CIPHER_get_block_size((*C.EVP_CIPHER)(c)))
}

// EVP_CIPHER_get_key_length 返回分组算法密钥长度（字节）。
func EVP_CIPHER_get_key_length(c unsafe.Pointer) int {
	return int(C.EVP_CIPHER_get_key_length((*C.EVP_CIPHER)(c)))
}

// EVP_CIPHER_get_iv_length 返回分组算法 IV 长度（字节）。
func EVP_CIPHER_get_iv_length(c unsafe.Pointer) int {
	return int(C.EVP_CIPHER_get_iv_length((*C.EVP_CIPHER)(c)))
}

// EVP_CIPHER_CTX_new 分配新的加密上下文。
func EVP_CIPHER_CTX_new() unsafe.Pointer {
	return unsafe.Pointer(C.EVP_CIPHER_CTX_new())
}

// EVP_CIPHER_CTX_free 释放加密上下文。
func EVP_CIPHER_CTX_free(ctx unsafe.Pointer) {
	C.EVP_CIPHER_CTX_free((*C.EVP_CIPHER_CTX)(ctx))
}

// EVP_CIPHER_CTX_set_padding 设置填充模式（1=PKCS7，0=无填充）。
func EVP_CIPHER_CTX_set_padding(ctx unsafe.Pointer, pad int) bool {
	return C.EVP_CIPHER_CTX_set_padding((*C.EVP_CIPHER_CTX)(ctx), C.int(pad)) == 1
}

// EVP_CipherInit_ex 初始化加密/解密上下文。
// key/iv 可传空切片表示不设置（ECB 模式 iv 为空）。enc 取 Encrypt 或 Decrypt。
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
func EVP_EncryptUpdate(ctx unsafe.Pointer, out, in []byte, outl *int) bool {
	return cipherUpdate(ctx, out, in, outl, true)
}

// EVP_DecryptUpdate 解密数据，输出写入 out，实际长度通过 outl 返回。
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
func EVP_EncryptFinal_ex(ctx unsafe.Pointer, out []byte, outl *int) bool {
	return cipherFinal(ctx, out, outl, true)
}

// EVP_DecryptFinal_ex 结束解密（校验填充），长度通过 outl 返回。
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
