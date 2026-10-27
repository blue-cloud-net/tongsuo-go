//go:build tongsuocli

// 本文件在 go test -tags tongsuocli 时编译；缺铜锁 CLI 时由 SkipIfNoOpenSSL
// 跳过。覆盖 `tongsuo list -xxx-algorithms` 与 `tongsuo list -providers`
// 的 Go 侧对拍。
//
// 对拍口径为**包含性断言**：本库报出的每个算法名都必须出现在 CLI 输出的
// 「Provided」段里（CLI 会把别名与 OID 也一并列出，故不做集合相等断言）。
// 另加一份必含清单，保证本库覆盖到关键算法。

package meta_test

import (
	"strings"
	"testing"

	"github.com/blue-cloud-net/tongsuo-go/internal/core"
	"github.com/blue-cloud-net/tongsuo-go/internal/testutil"
	"github.com/blue-cloud-net/tongsuo-go/meta"
)

// parseProvidedAlgNames 从 `openssl list -xxx-algorithms` 的输出中解析
// 「Provided」段的算法名集合（小写归一，便于大小写不敏感的比较）。
// 行格式形如 "  { OID, NAME, ALIAS } @ default" 或 "  NAME @ default"；
// Legacy 段的 "X => Y" 别名行被忽略。
// 部分算法族（signature / key-exchange / kem）的输出没有段标题，
// 此时整份输出都按 Provided 段处理。
//
// parseProvidedAlgNames parses the algorithm names of the "Provided"
// section of `openssl list -xxx-algorithms` (lower-cased so that the
// comparison can be case-insensitive). Lines look like
// "  { OID, NAME, ALIAS } @ default" or "  NAME @ default"; the "X => Y"
// alias lines of the Legacy section are ignored. Some families
// (signature / key-exchange / kem) print no section header at all, in
// which case the whole output is treated as the Provided section.
func parseProvidedAlgNames(t *testing.T, out string) map[string]struct{} {
	t.Helper()
	names := map[string]struct{}{}
	inProvided := true
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			// 顶格的是段标题（"Provided:" / "Legacy:" / ...）。
			switch {
			case strings.HasPrefix(trimmed, "Legacy"):
				inProvided = false
			case strings.HasPrefix(trimmed, "Provided"):
				inProvided = true
			}
			continue
		}
		if !inProvided {
			continue
		}
		if strings.Contains(trimmed, "=>") {
			continue
		}
		if idx := strings.Index(trimmed, " @ "); idx >= 0 {
			trimmed = trimmed[:idx]
		}
		trimmed = strings.TrimSpace(trimmed)
		trimmed = strings.TrimPrefix(trimmed, "{")
		trimmed = strings.TrimSuffix(trimmed, "}")
		for _, part := range strings.Split(trimmed, ",") {
			name := strings.TrimSpace(part)
			if name == "" {
				continue
			}
			names[strings.ToLower(name)] = struct{}{}
		}
	}
	return names
}

// TestAlgorithmEnumerationAgainstCLI 验证本库枚举的算法名都出现在
// `openssl list -xxx-algorithms` 的输出里。
//
// TestAlgorithmEnumerationAgainstCLI verifies that every algorithm name
// reported by this library also appears in `openssl list -xxx-algorithms`.
func TestAlgorithmEnumerationAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	tests := []struct {
		name string
		arg  string
		got  []string
	}{
		{"digest", "-digest-algorithms", meta.Digests()},
		{"cipher", "-cipher-algorithms", meta.Ciphers()},
		{"mac", "-mac-algorithms", meta.MACs()},
		{"kdf", "-kdf-algorithms", meta.KDFs()},
		{"signature", "-signature-algorithms", meta.Signatures()},
		{"keyexch", "-key-exchange-algorithms", meta.KeyExchanges()},
		{"kem", "-kem-algorithms", meta.KEMs()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := testutil.RunOpenSSL([]string{"list", tt.arg}, nil)
			if err != nil {
				t.Fatalf("openssl list %s: %v", tt.arg, err)
			}
			cli := parseProvidedAlgNames(t, string(out))
			if len(cli) == 0 {
				t.Fatalf("openssl list %s: no provided algorithm parsed", tt.arg)
			}
			for _, name := range tt.got {
				if _, ok := cli[strings.ToLower(name)]; !ok {
					t.Errorf("%s: %q reported by the library but absent from the CLI output", tt.name, name)
				}
			}
		})
	}
}

// TestTLSGroupsAgainstCLI 验证本库枚举的 TLS 组都出现在
// `openssl list -tls-groups` 的输出里。
//
// TestTLSGroupsAgainstCLI verifies that every TLS group reported by this
// library also appears in `openssl list -tls-groups`.
func TestTLSGroupsAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)
	// Tongsuo 8.4.0 的 `list` 子命令没有 -tls-groups 选项，本库也不枚举。
	// Tongsuo 8.4.0's `list` has no -tls-groups option and this library
	// does not enumerate groups either.
	if !core.TLSGroupsSupported() {
		t.Skip("this build has no TLS group enumeration (list -tls-groups, OpenSSL < 3.2)")
	}

	out, err := testutil.RunOpenSSL([]string{"list", "-tls-groups"}, nil)
	if err != nil {
		t.Fatalf("openssl list -tls-groups: %v", err)
	}
	cli := map[string]struct{}{}
	for _, name := range strings.Split(strings.TrimSpace(string(out)), ":") {
		name = strings.TrimSpace(name)
		if name != "" {
			cli[name] = struct{}{}
		}
	}
	if len(cli) == 0 {
		t.Fatal("openssl list -tls-groups: no group parsed")
	}
	for _, name := range meta.TLSGroups() {
		if _, ok := cli[name]; !ok {
			t.Errorf("tls group %q reported by the library but absent from the CLI output", name)
		}
	}
}

// TestProvidersAgainstCLI 验证本库枚举的 provider 都出现在
// `openssl list -providers` 的输出里。
//
// TestProvidersAgainstCLI verifies that every provider reported by this
// library also appears in `openssl list -providers`.
func TestProvidersAgainstCLI(t *testing.T) {
	testutil.SkipIfNoOpenSSL(t)

	out, err := testutil.RunOpenSSL([]string{"list", "-providers"}, nil)
	if err != nil {
		t.Fatalf("openssl list -providers: %v", err)
	}
	cli := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Providers:") {
			continue
		}
		if strings.HasPrefix(trimmed, "name:") ||
			strings.HasPrefix(trimmed, "version:") ||
			strings.HasPrefix(trimmed, "status:") {
			continue
		}
		cli[trimmed] = struct{}{}
	}
	if len(cli) == 0 {
		t.Fatalf("openssl list -providers: no provider parsed:\n%s", string(out))
	}
	for _, p := range meta.Providers() {
		if _, ok := cli[p.Name]; !ok {
			t.Errorf("provider %q reported by the library but absent from the CLI output", p.Name)
		}
	}
}
