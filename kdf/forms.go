package kdf

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// DeriveTo 按算法名派生并把结果按 sink 的编码写出。
// 参数语义与返回值同 Derive；额外支持把结果写入文件 / 标准输出 /
// 自定义 writer（sink 为 nil 等价于标准输出）。本函数不调用 sink.Close。
//
// DeriveTo derives by algorithm name and writes the result using sink's
// encoding. Parameters and errors match Derive; it additionally supports
// writing to a file, standard output or a caller-supplied writer (a nil
// sink means standard output). The function does not close sink.
func DeriveTo(name string, opts *Options, sink *meta.Sink) error {
	out, err := Derive(name, opts)
	if err != nil {
		return err
	}
	if _, err := sink.Write(out); err != nil {
		return fmt.Errorf("kdf: %s: write: %w", name, err)
	}
	return nil
}
