package asn1

import (
	"errors"
	"fmt"
)

// ErrDepthLimit 表示 DER 构造类型超过允许层数。
//
// ErrDepthLimit reports that DER constructed nesting exceeds its limit.
var ErrDepthLimit = errors.New("asn1: DER depth limit exceeded")

// ErrNodeLimit 表示 DER 节点数超过限额（包含根和叶）。
//
// ErrNodeLimit reports that the DER node count, including root and leaves, exceeds its limit.
var ErrNodeLimit = errors.New("asn1: DER node limit exceeded")

// ParseWithLimits 按正数深度和节点限额解析完整 DER；深度计构造类型层数。
// 返回的 Value 引用输入切片；超限错误可用 errors.Is 识别，不返回部分树。
//
// ParseWithLimits parses complete DER with positive constructed-depth and node limits.
// Values alias the input; errors.Is identifies limit errors and no partial tree is returned.
func ParseWithLimits(der []byte, maxDepth, maxNodes int) (*Node, error) {
	if maxDepth <= 0 || maxNodes <= 0 {
		return nil, fmt.Errorf("asn1: limits must be positive")
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("asn1: empty DER")
	}
	root, used, err := parseHeader(der, 0)
	if err != nil {
		return nil, err
	}
	if used != len(der) {
		return nil, fmt.Errorf("asn1: %d trailing bytes after top-level value", len(der)-used)
	}
	type frame struct {
		node               *Node
		cursor, end, depth int
	}
	stack := []frame{{root, used - root.Length, used, 0}}
	count := 1
	for len(stack) > 0 {
		f := &stack[len(stack)-1]
		if !f.node.Constructed {
			stack = stack[:len(stack)-1]
			continue
		}
		if f.depth >= maxDepth {
			return nil, fmt.Errorf("%w at offset %d", ErrDepthLimit, f.node.Offset)
		}
		if f.cursor == f.end {
			stack = stack[:len(stack)-1]
			continue
		}
		if count >= maxNodes {
			return nil, fmt.Errorf("%w at offset %d", ErrNodeLimit, f.cursor)
		}
		child, size, err := parseHeader(der[f.cursor:f.end], f.cursor)
		if err != nil {
			return nil, err
		}
		at, depth := f.cursor, f.depth+1
		f.node.Children = append(f.node.Children, child)
		f.cursor += size
		count++
		stack = append(stack, frame{child, at + size - child.Length, at + size, depth})
	}
	return root, nil
}
