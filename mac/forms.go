package mac

import (
	"fmt"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// SumSource 按算法名计算 src 全部内容的 MAC 标签。
// src 为 nil 时等价于标准输入。未知算法名返回 ErrUnknownAlgorithm；
// 缺少算法必需参数返回 ErrInvalidOptions。
//
// SumSource computes the MAC tag of everything src yields for the named
// algorithm. A nil src is equivalent to standard input. Unknown names
// return ErrUnknownAlgorithm; a missing mandatory parameter returns
// ErrInvalidOptions.
func SumSource(name string, key []byte, src *meta.Source, opts *Options) ([]byte, error) {
	r, err := src.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return SumReader(name, key, r, opts)
}

// SumTo 按算法名计算 src 全部内容的 MAC 标签，并按 sink 的编码写出。
// sink 为 nil 时等价于标准输出；本函数不调用 sink.Close。
//
// SumTo computes the MAC tag of everything src yields and writes it using
// sink's encoding. A nil sink is equivalent to standard output; the
// function does not close sink.
func SumTo(name string, key []byte, src *meta.Source, sink *meta.Sink, opts *Options) error {
	tag, err := SumSource(name, key, src, opts)
	if err != nil {
		return err
	}
	if _, err := sink.Write(tag); err != nil {
		return fmt.Errorf("mac: %s: write: %w", name, err)
	}
	return nil
}

// SumFile 按算法名计算硬盘文件的 MAC 标签（mac -file 便捷入口）。
// path 为 "-" 时读标准输入。
//
// SumFile computes the MAC tag of an on-disk file for the named
// algorithm (the `mac -file` convenience path). A path of "-" reads
// standard input.
func SumFile(name string, key []byte, path string, opts *Options) ([]byte, error) {
	src, err := meta.NewFileSource(path)
	if err != nil {
		return nil, err
	}
	return SumSource(name, key, src, opts)
}
