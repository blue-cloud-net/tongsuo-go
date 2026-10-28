package meta

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrNoPEMBlock 表示输入中没有任何 PEM 块。
//
// ErrNoPEMBlock reports that the input contains no PEM block at all.
var ErrNoPEMBlock = errors.New("meta: no PEM block found")

// SplitPEM 把 data 拆成 PEM 块列表，对应铜锁 CLI 一次读入多个 PEM 块
// （证书链、私钥与证书混合、CRL 列表等）以及 `crl2pkcs7` 这类流水线的场景。
//
// 语义：
//   - 块之间的空白、注释与任何非 PEM 文本都会被忽略（与 openssl 一致）；
//   - 返回的块顺序与输入顺序一致；
//   - 输入不含任何 PEM 块时返回包装 ErrNoPEMBlock 的错误，而不是空切片——
//     避免把「格式错误」误判成「文件为空」。
//
// SplitPEM splits data into its PEM blocks, mirroring the Tongsuo CLI case
// of reading several PEM blocks at once (a certificate chain, a private
// key mixed with its certificate, a CRL list) and pipelines such as
// `crl2pkcs7`.
//
// Semantics:
//   - whitespace, comments and any non-PEM text between blocks are ignored
//     (matching openssl);
//   - blocks are returned in input order;
//   - an input without any PEM block returns an error wrapping
//     ErrNoPEMBlock rather than an empty slice, so "malformed" is not
//     mistaken for "empty file".
func SplitPEM(data []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		return nil, ErrNoPEMBlock
	}
	return blocks, nil
}

// SplitPEMByType 按 PEM 块类型分组的便捷入口（键为 "CERTIFICATE" /
// "PRIVATE KEY" / "X509 CRL" 等，与输入中出现的 Type 原文一致）。
// 同类型的多个块按输入顺序保留；输入不含 PEM 块时返回包装 ErrNoPEMBlock 的错误。
//
// SplitPEMByType groups the PEM blocks by their Type (the keys are the
// verbatim "CERTIFICATE" / "PRIVATE KEY" / "X509 CRL" values found in the
// input). Blocks of the same type keep their input order; an input
// without any PEM block returns an error wrapping ErrNoPEMBlock.
func SplitPEMByType(data []byte) (map[string][]*pem.Block, error) {
	blocks, err := SplitPEM(data)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]*pem.Block, len(blocks))
	for _, b := range blocks {
		out[b.Type] = append(out[b.Type], b)
	}
	return out, nil
}

// DecodePEMFirst 返回第一个 PEM 块的 DER 内容与类型。
// 输入不含 PEM 块时返回包装 ErrNoPEMBlock 的错误。
//
// DecodePEMFirst returns the DER bytes and the type of the first PEM
// block. An input without any PEM block returns an error wrapping
// ErrNoPEMBlock.
func DecodePEMFirst(data []byte) (der []byte, blockType string, err error) {
	blocks, err := SplitPEM(data)
	if err != nil {
		return nil, "", err
	}
	return blocks[0].Bytes, blocks[0].Type, nil
}

// EncodePEM 把 DER 内容按指定块类型编码为 PEM（每行 64 字符、无额外头部），
// 与 openssl 的默认 PEM 输出形态一致。
// der 为空返回错误。
//
// EncodePEM encodes DER bytes as PEM under the given block type (64
// characters per line, no extra headers), matching the default PEM output
// of openssl. An empty der returns an error.
func EncodePEM(der []byte, blockType string) ([]byte, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("meta: empty DER payload")
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return nil, fmt.Errorf("meta: PEM encode: %w", err)
	}
	return buf.Bytes(), nil
}
