package x509

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
)

// Name 表示证书主题/签发者名字，支持链式构建。
//
// Name represents a certificate subject or issuer name and supports fluent construction via Add.
type Name struct {
	name *core.Name
}

// NameEntry 表示名字中的一个 RDN 条目。
//
// Nid 为属性 NID；Field 为字段短名（如 "CN"、"O"）；Value 为 UTF-8 编码的属性值。
//
// NameEntry represents a single RDN attribute inside a Name.
//
// Nid is the attribute NID, Field is the short name (for example "CN" or "O"),
// and Value is the UTF-8 attribute value.
type NameEntry struct {
	Nid   int    // 字段 NID
	Field string // 字段短名，如 "CN"、"O"
	Value string // 字段值（UTF-8）
}

// NewName 创建空名字。
//
// NewName creates an empty Name. Use Add to populate it.
func NewName() *Name {
	n, err := core.NewName()
	if err != nil {
		panic(err)
	}
	return &Name{name: n}
}

// Add 添加名字字段并返回自身（链式）。
// field 取 "CN"、"C"、"O"、"OU"、"L"、"ST"、"serialNumber"、"emailAddress" 等。
//
// ⚠️ 本方法对**编程错误**会 panic：对来自用户的不可信输入请改用 TryAdd。
// 由内部链式构造时（NewName().Add(...)）传入固定短名不应触发错误。
//
// Add appends a relative distinguished name attribute and returns the same Name for chaining. field accepts short names such as "CN", "C", "O", "OU", "L", "ST", "serialNumber", and "emailAddress".
//
// ⚠️ This method panics on PROGRAMMING errors (invalid field name,
// overlong value). For untrusted user input use TryAdd instead; for
// hard-coded builder chains (NewName().Add("CN", "...")) this branch
// is not reached.
func (n *Name) Add(field, value string) *Name {
	if err := n.name.AddEntry(field, value); err != nil {
		panic("x509: Name.Add: " + err.Error())
	}
	return n
}

// TryAdd 是 Add 的非 panic 版本：字段非法或值超长时返回 error，调用方
// 可决定继续或回滚。
//
// TryAdd is the non-panicking variant of Add. It returns the underlying
// error (invalid field name, overlong value, ...) so callers handling
// untrusted input can react instead of crashing.
func (n *Name) TryAdd(field, value string) error {
	if n == nil || n.name == nil {
		return fmt.Errorf("x509: nil Name")
	}
	return n.name.AddEntry(field, value)
}

// Entries 返回名字的全部 RDN 条目（保持证书中的顺序）。
//
// Entries returns every RDN attribute of the Name in the order they were added.
func (n *Name) Entries() []NameEntry {
	es := n.name.Entries()
	out := make([]NameEntry, 0, len(es))
	for _, e := range es {
		out = append(out, NameEntry{Nid: e.Nid, Field: e.Field, Value: e.Value})
	}
	return out
}

// Get 返回指定字段短名（如 "CN"、"O"）的值；未找到返回空串。
//
// Get returns the value of the attribute with the given short name (for example "CN" or "O"), or an empty string when no such attribute is present.
func (n *Name) Get(field string) string { return n.name.Get(field) }

// Nid 返回指定字段短名（如 "CN"、"O"）对应的 NID，未知字段返回 0（与 native.NidUndef 一致）。
//
// Nid returns the OpenSSL NID for the given short name (for example "CN" or "O"), or 0 (matching native.NidUndef) when the name is unknown.
func (n *Name) Nid(field string) int { return n.name.Nid(field) }

// Len 返回 Name 中的 RDN 条目数（已关闭或 nil Name 返回 0）。
//
// Len returns the number of RDN entries in the Name (0 for a nil or closed Name).
func (n *Name) Len() int { return n.name.Len() }

// String 返回名字的完整单行文本（如 "/CN=example.com/O=Example Org"）。
//
// String returns the Name as a single-line string in OpenSSL-style format (for example "/CN=example.com/O=Example Org").
func (n *Name) String() string { return n.name.String() }
