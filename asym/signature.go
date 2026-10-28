package asym

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// 签名表示转换（DER ↔ 裸 r‖s）
//
// SM2 与 ECDSA 的签名有两个常见字节表示：
//
//   - der：ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`，长度可变（r 或 s 的
//     最高位为 0 时 DER 会省略前导 0x00 字节，因此同一逻辑签名可能是 70/71/72
//     字节）；
//   - raw：定长的 `r ‖ s`，每分量宽度由曲线阶决定——SM2 / P-256 / secp256k1
//     为 32+32=64 字节，P-384 为 48+48=96，P-521 为 66+66=132。
//
// 关键约束：DER 与 raw 都**不携带曲线信息**，所以从 DER 转 raw 必须由调用方给出
// 每分量宽度（width）。本包不猜宽度。
//
// 适用范围：仅 SM2 与 ECDSA。RSA 的签名本身就是裸字节串（没有 DER 包装），
// Ed25519 / Ed448 恒为定长裸签名，两者都不适用本组函数。
//
// Signature representation conversion (DER to/from bare r‖s)
//
// SM2 and ECDSA signatures have two common byte representations:
//
//   - der: the ASN.1 form `SEQUENCE { INTEGER r, INTEGER s }`, whose length
//     varies (DER drops the leading 0x00 when the high bit of r or s is
//     clear, so the same logical signature may be 70/71/72 bytes);
//   - raw: the fixed-width `r ‖ s`, where the per-component width follows
//     from the curve order — 32+32=64 bytes for SM2 / P-256 / secp256k1,
//     48+48=96 for P-384 and 66+66=132 for P-521.
//
// Key constraint: neither DER nor raw carries the curve identity, so
// converting DER to raw requires the caller to supply the per-component
// width. This package never guesses it.
//
// Applicability: SM2 and ECDSA only. RSA signatures are already bare byte
// strings (no DER wrapper) and Ed25519 / Ed448 signatures are always
// fixed-width raw values, so neither family applies to these helpers.

// signatureRS 是 DER 编解码的中间结构（asn1 只认导出字段）。
//
// signatureRS is the intermediate struct used for DER encoding and
// decoding (encoding/asn1 only handles exported fields).
type signatureRS struct {
	R *big.Int
	S *big.Int
}

// parseSignatureDER 严格解析 `SEQUENCE { INTEGER r, INTEGER s }`。
// 拒绝尾随字节、负数与非最小编码以外的结构。
//
// parseSignatureDER strictly parses `SEQUENCE { INTEGER r, INTEGER s }`,
// rejecting trailing bytes, negative values and any other structure.
func parseSignatureDER(sig []byte) (r, s []byte, err error) {
	var rs signatureRS
	rest, err := asn1.Unmarshal(sig, &rs)
	if err != nil {
		return nil, nil, fmt.Errorf("asym: signature: invalid DER: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("asym: signature: invalid DER: %d trailing bytes", len(rest))
	}
	if rs.R == nil || rs.S == nil {
		return nil, nil, fmt.Errorf("asym: signature: invalid DER: missing r or s")
	}
	if rs.R.Sign() < 0 || rs.S.Sign() < 0 {
		return nil, nil, fmt.Errorf("asym: signature: invalid DER: negative component")
	}
	return rs.R.Bytes(), rs.S.Bytes(), nil
}

// buildSignatureDER 把 r、s 编码为最短形式的 DER。
// r、s 为无符号大端字节（允许前导 0x00，会被规范化掉）。
//
// buildSignatureDER encodes r and s as DER in the shortest form. r and s
// are unsigned big-endian bytes; any leading 0x00 is normalized away.
func buildSignatureDER(r, s []byte) ([]byte, error) {
	if len(r) == 0 || len(s) == 0 {
		return nil, fmt.Errorf("asym: signature: empty r or s")
	}
	ri := new(big.Int).SetBytes(r)
	si := new(big.Int).SetBytes(s)
	if ri.Sign() == 0 || si.Sign() == 0 {
		return nil, fmt.Errorf("asym: signature: zero component")
	}
	der, err := asn1.Marshal(signatureRS{R: ri, S: si})
	if err != nil {
		return nil, fmt.Errorf("asym: signature: DER encode: %w", err)
	}
	return der, nil
}

// SignatureParts 把 DER 签名拆成两个大端分量 r、s（最小长度，不做定长补齐）。
// 输入必须是 `SEQUENCE { INTEGER r, INTEGER s }`；其它结构返回错误。
// 需要定长的 `r‖s` 请用 FormatSignature。
//
// 适用范围：仅 SM2 与 ECDSA（见本节开头的说明）。
//
// SignatureParts splits a DER signature into the two big-endian
// components r and s (minimal length, no fixed-width padding). The input
// must be `SEQUENCE { INTEGER r, INTEGER s }`; anything else returns an
// error. Use FormatSignature when a fixed-width `r‖s` is required.
//
// Applicability: SM2 and ECDSA only (see the note at the top of this
// section).
func SignatureParts(sig []byte) (r, s []byte, err error) {
	return parseSignatureDER(sig)
}

// SignatureDER 把两个大端分量 r、s 编码为 DER 签名。
// r、s 允许带前导 0x00（会被规范化）；空分量或数值为 0 返回错误。
//
// SignatureDER encodes the big-endian components r and s as a DER
// signature. Leading 0x00 bytes are normalized away; an empty or zero
// component returns an error.
func SignatureDER(r, s []byte) ([]byte, error) {
	return buildSignatureDER(r, s)
}

// FormatSignature 在签名的 "der" 与 "raw" 表示之间转换。
//
//   - from / to 只能取 "der" 或 "raw"；两者相同时返回入参的副本。
//   - width 是 **每个分量**的字节数（SM2 / P-256 = 32，P-384 = 48，P-521 = 66）。
//     从 "der" 转换时必须显式给出（DER 不携带曲线信息，无法推断）；从 "raw"
//     转换时可传 0，此时按入参长度的一半推断，传非 0 则必须与之一致。
//   - r 或 s 超出 width 字节时返回错误（说明宽度与曲线不匹配）。
//
// 适用范围：仅 SM2 与 ECDSA。
//
// FormatSignature converts a signature between the "der" and "raw"
// representations.
//
//   - from and to must be "der" or "raw"; when they are equal, a copy of
//     the input is returned.
//   - width is the number of bytes **per component** (SM2 / P-256 = 32,
//     P-384 = 48, P-521 = 66). It is mandatory when converting from "der"
//     because DER carries no curve identity. When converting from "raw" it
//     may be 0, in which case it is inferred as half the input length; a
//     non-zero value must agree with that.
//   - A component wider than width returns an error, signalling a width
//     that does not match the curve.
//
// Applicability: SM2 and ECDSA only.
func FormatSignature(sig []byte, from, to string, width int) ([]byte, error) {
	switch from {
	case "der", "raw":
	default:
		return nil, fmt.Errorf("asym: signature: unknown format %q (want der/raw)", from)
	}
	switch to {
	case "der", "raw":
	default:
		return nil, fmt.Errorf("asym: signature: unknown format %q (want der/raw)", to)
	}
	if from == to {
		return append([]byte{}, sig...), nil
	}

	if from == "der" {
		r, s, err := parseSignatureDER(sig)
		if err != nil {
			return nil, err
		}
		if width <= 0 {
			return nil, fmt.Errorf("asym: signature: der->raw needs an explicit component width")
		}
		return joinRawComponents(r, s, width)
	}

	// from == "raw"（输入必须是偶数长度，左右各半）
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("asym: signature: raw length %d is not an even number of bytes", len(sig))
	}
	inferred := len(sig) / 2
	if width == 0 {
		width = inferred
	} else if width != inferred {
		return nil, fmt.Errorf("asym: signature: raw length %d does not match width %d", len(sig), width)
	}
	r := sig[:width]
	s := sig[width:]
	return buildSignatureDER(r, s)
}

// joinRawComponents 把 r、s 定长左补零到 width 后拼接。
//
// joinRawComponents left-pads r and s to width and concatenates them.
func joinRawComponents(r, s []byte, width int) ([]byte, error) {
	if len(r) > width || len(s) > width {
		return nil, fmt.Errorf("asym: signature: component wider than %d bytes (r=%d, s=%d)",
			width, len(r), len(s))
	}
	out := make([]byte, 2*width)
	copy(out[width-len(r):width], r)
	copy(out[2*width-len(s):], s)
	return out, nil
}
