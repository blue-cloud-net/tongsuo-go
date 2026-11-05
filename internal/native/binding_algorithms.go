package native

/*
#include "algorithms.h"
*/
import "C"
import "unsafe"

// X_EVP_DigestSignVerifyInit_instance 设置 EdDSA 实例及上下文；-2 表示参数不可用。
// X_EVP_DigestSignVerifyInit_instance sets EdDSA instance/context; -2 means unavailable parameters.
func X_EVP_DigestSignVerifyInit_instance(ctx, key unsafe.Pointer, instance string, context []byte, sign bool) int {
	name, freeName := cstr(instance)
	defer freeName()
	data, freeData := cbytes(context)
	defer freeData()
	return int(C.X_EVP_DigestSignVerifyInit_instance((*C.EVP_MD_CTX)(ctx), (*C.EVP_PKEY)(key), name,
		(*C.uchar)(data), C.size_t(len(context)), C.int(boolToInt(sign))))
}

// X_EVP_PKEY_SM2DH 使用双方静态与临时密钥派生 SM2DH 密钥，参数由 C 栈持有。
// X_EVP_PKEY_SM2DH derives SM2DH with static/ephemeral keys using C-owned parameters.
func X_EVP_PKEY_SM2DH(ephemeral, peerEphemeral, selfStatic, peerStatic unsafe.Pointer, initiator bool, selfID, peerID, out []byte) int {
	self, freeSelf := cbytes(selfID)
	defer freeSelf()
	peer, freePeer := cbytes(peerID)
	defer freePeer()
	return int(C.X_EVP_PKEY_SM2DH((*C.EVP_PKEY)(ephemeral), (*C.EVP_PKEY)(peerEphemeral),
		(*C.EVP_PKEY)(selfStatic), (*C.EVP_PKEY)(peerStatic), C.int(boolToInt(initiator)),
		(*C.uchar)(self), C.size_t(len(selfID)), (*C.uchar)(peer), C.size_t(len(peerID)),
		(*C.uchar)(bytesPtr(out)), C.size_t(len(out))))
}
