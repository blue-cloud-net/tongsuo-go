package core

import (
	"bytes"
	"encoding/pem"
	"errors"
	"unicode"
)

// DecodeLeadingPEM 解析首个 PEM 块。块之前和块之间只允许空白。
//
// DecodeLeadingPEM reads the first PEM block and permits only whitespace before or between blocks.
func DecodeLeadingPEM(data []byte) (*pem.Block, []byte, error) {
	data = bytes.TrimLeftFunc(data, unicode.IsSpace)
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, nil, errors.New("expected PEM block")
	}
	block, rest := pem.Decode(data)
	if block == nil || bytes.Contains(data[:len(data)-len(rest)], []byte("\n-----BEGIN")) {
		return nil, nil, errors.New("malformed PEM block")
	}
	return block, rest, nil
}
