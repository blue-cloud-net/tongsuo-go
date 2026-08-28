package x509

import "github.com/blue-cloud-net/tongsuo-go/internal/core"

// Name 表示证书主题/签发者名字，支持链式构建。
type Name struct {
	name *core.Name
}

// NameEntry 表示名字中的一个 RDN 条目。
type NameEntry struct {
	Nid   int    // 字段 NID
	Field string // 字段短名，如 "CN"、"O"
	Value string // 字段值（UTF-8）
}

// NewName 创建空名字。
func NewName() *Name {
	n, err := core.NewName()
	if err != nil {
		panic(err)
	}
	return &Name{name: n}
}

// Add 添加名字字段并返回自身（链式）。
// field 取 "CN"、"C"、"O"、"OU"、"L"、"ST"、"serialNumber"、"emailAddress" 等。
func (n *Name) Add(field, value string) *Name {
	if err := n.name.AddEntry(field, value); err != nil {
		panic(err)
	}
	return n
}

// Entries 返回名字的全部 RDN 条目（保持证书中的顺序）。
func (n *Name) Entries() []NameEntry {
	es := n.name.Entries()
	out := make([]NameEntry, 0, len(es))
	for _, e := range es {
		out = append(out, NameEntry{Nid: e.Nid, Field: e.Field, Value: e.Value})
	}
	return out
}

// Get 返回指定字段短名（如 "CN"、"O"）的值；未找到返回空串。
func (n *Name) Get(field string) string { return n.name.Get(field) }

// String 返回名字的完整单行文本（如 "/CN=example.com/O=Example Org"）。
func (n *Name) String() string { return n.name.String() }
