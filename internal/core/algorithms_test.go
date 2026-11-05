package core

import (
	"errors"
	"testing"
)

// TestEdDSAInitErrorClassification 验证未支持参数与实际原生初始化失败分别保留错误类别。
//
// TestEdDSAInitErrorClassification checks that unavailable parameters and native initialization failures retain distinct error categories.
func TestEdDSAInitErrorClassification(t *testing.T) {
	key, err := GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	_, err = key.SignEdDSAInstance([]byte("message"), "invalid-instance", nil)
	if err == nil {
		t.Fatal("invalid instance accepted")
	}
	if VersionNum() < 0x30500000 {
		if !errors.Is(err, ErrAlgorithmUnavailable) {
			t.Fatalf("unavailable instance: %v", err)
		}
		return
	}
	var op *OpError
	if errors.Is(err, ErrAlgorithmUnavailable) || !errors.As(err, &op) {
		t.Fatalf("native initialization failure misclassified: %v", err)
	}
}
