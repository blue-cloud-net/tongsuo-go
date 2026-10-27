package digest

import (
	"fmt"
	"io"

	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// SumSource 按算法名计算 src 全部内容的摘要。
// src 为 nil 时等价于标准输入；输出长度等于该算法的 Size。
// 未知算法名返回 ErrUnknownAlgorithm，读取失败返回包装错误。
// 本函数不关闭 src 之外的任何资源（Open 得到的读取器会关闭）。
//
// SumSource computes the digest of everything src yields for the named
// algorithm. A nil src is equivalent to standard input; the returned
// slice has the algorithm's Size. Unknown names return
// ErrUnknownAlgorithm and read failures are wrapped. The reader obtained
// from src is closed.
func SumSource(name string, src *meta.Source) ([]byte, error) {
	r, err := src.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return SumReader(name, r)
}

// SumTo 按算法名计算 src 全部内容的摘要，并按 sink 的编码写出。
// sink 为 nil 时等价于标准输出；sink 的编码（raw / hex / base64）由
// SetEncoding 预先设定。本函数不调用 sink.Close，调用方负责收尾。
//
// SumTo computes the digest of everything src yields and writes it using
// sink's encoding. A nil sink is equivalent to standard output; the
// encoding (raw / hex / base64) is selected beforehand via SetEncoding.
// The function does not close sink; the caller owns that.
func SumTo(name string, src *meta.Source, sink *meta.Sink) error {
	sum, err := SumSource(name, src)
	if err != nil {
		return err
	}
	if _, err := sink.Write(sum); err != nil {
		return fmt.Errorf("digest: %s: write: %w", name, err)
	}
	return nil
}

// SumFile 按算法名计算硬盘文件的摘要（sum -file 便捷入口）。
// path 为 "-" 时读标准输入。等价于 SumSource(name, NewFileSource(path))。
//
// SumFile computes the digest of an on-disk file for the named algorithm
// (the `sum -file` convenience path). A path of "-" reads standard input;
// it is equivalent to SumSource(name, NewFileSource(path)).
func SumFile(name, path string) ([]byte, error) {
	src, err := meta.NewFileSource(path)
	if err != nil {
		return nil, err
	}
	return SumSource(name, src)
}

// SumReaderTo 从 r 流式计算摘要并按 sink 的编码写出。
// 供调用方直接持有 io.Reader 时使用；与 SumTo 的区别是不经过 meta.Source。
//
// SumReaderTo streams r, computes the digest and writes it using sink's
// encoding. It exists for callers that already hold an io.Reader and
// differs from SumTo only in bypassing meta.Source.
func SumReaderTo(name string, r io.Reader, sink *meta.Sink) error {
	sum, err := SumReader(name, r)
	if err != nil {
		return err
	}
	if _, err := sink.Write(sum); err != nil {
		return fmt.Errorf("digest: %s: write: %w", name, err)
	}
	return nil
}
