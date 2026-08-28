package x509

import "github.com/blue-cloud-net/tongsuo-go/internal/core"

// convertEntries 将 core.NameEntry 切片转为 API 层 NameEntry 切片。
func convertEntries(es []core.NameEntry) []NameEntry {
	out := make([]NameEntry, 0, len(es))
	for _, e := range es {
		out = append(out, NameEntry{Nid: e.Nid, Field: e.Field, Value: e.Value})
	}
	return out
}

// convertExtensions 将 core.Extension 切片转为 API 层 Extension 切片。
func convertExtensions(es []core.Extension) []Extension {
	out := make([]Extension, 0, len(es))
	for _, e := range es {
		out = append(out, Extension{
			Nid:      e.Nid,
			Field:    e.Field,
			Critical: e.Critical,
			Value:    e.Value,
			Data:     e.Data,
		})
	}
	return out
}
