package pkcs12

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func complexTool(t *testing.T) string {
	t.Helper()
	home := os.Getenv("TONGSUO_HOME")
	if home == "" {
		home = "/opt/tongsuo"
	}
	tool := filepath.Join(t.TempDir(), "p12-fixture")
	lib := filepath.Join(home, "lib")
	if _, err := os.Stat(lib); err != nil {
		lib = filepath.Join(home, "lib64")
	}
	compiler := strings.Fields(os.Getenv("CC"))
	if len(compiler) == 0 {
		compiler = []string{"cc"}
	}
	args := append([]string{}, compiler[1:]...)
	args = append(args, strings.Fields(os.Getenv("CGO_CPPFLAGS"))...)
	args = append(args, strings.Fields(os.Getenv("CGO_CFLAGS"))...)
	args = append(args, "-Wno-deprecated-declarations", "-I"+filepath.Join(home, "include"), "testdata/complex.c")
	args = append(args, strings.Fields(os.Getenv("CGO_LDFLAGS"))...)
	args = append(args, "-L"+lib, "-Wl,-rpath,"+lib, "-lcrypto", "-o", tool)
	if out, err := exec.Command(compiler[0], args...).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, out)
	}
	return tool
}
func runComplexTool(t *testing.T, tool, op, path, pass string) []byte {
	t.Helper()
	out, err := exec.Command(tool, op, path, pass).CombinedOutput()
	if err != nil {
		t.Fatalf("fixture %s: %v\n%s", op, err, out)
	}
	return out
}

// TestComplexPasswordChanges 验证相关操作的正确性、边界与错误处理。
//
// TestComplexPasswordChanges checks operation correctness, boundaries and error handling.
func TestComplexPasswordChanges(t *testing.T) {
	tool := complexTool(t)
	dir := t.TempDir()
	original := filepath.Join(dir, "original.p12")
	runComplexTool(t, tool, "create", original, "old")
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := runComplexTool(t, tool, "snapshot", original, "old")
	if !bytes.Contains(snapshot, []byte("depth=2")) || bytes.Count(snapshot, []byte("pkcs8ShroudedKeyBag")) != 2 || !bytes.Contains(snapshot, []byte("crlBag")) || !bytes.Contains(snapshot, []byte("secretBag")) {
		t.Fatalf("fixture lacks complex content: %s", snapshot)
	}
	for _, pbe := range []string{"", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "PBE-SHA1-3DES"} {
		t.Run(pbe, func(t *testing.T) {
			var changed []byte
			var err error
			if pbe == "" {
				changed, err = ChangePassword(data, "old", "new")
			} else {
				changed, err = ChangePasswordWithOptions(data, &Options{ReadPass: "old", WritePass: "new", PBE: pbe, Iterations: 5678})
			}
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(changed, data) {
				t.Fatal("password change did not reencrypt")
			}
			path := filepath.Join(t.TempDir(), "changed.p12")
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			after := runComplexTool(t, tool, "snapshot", path, "new")
			if !bytes.Equal(snapshot, after) {
				t.Fatalf("content/attributes changed\nbefore %s\nafter %s", snapshot, after)
			}
			if out, err := exec.Command(tool, "snapshot", path, "old").CombinedOutput(); err == nil {
				t.Fatalf("old password accepted: %s", out)
			}
			round, err := ChangePassword(changed, "new", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, round, 0600); err != nil {
				t.Fatal(err)
			}
			if after := runComplexTool(t, tool, "snapshot", path, ""); !bytes.Equal(snapshot, after) {
				t.Fatal("empty password changed payload")
			}
		})
	}
	if out, err := ChangePasswordWithOptions(data, &Options{ReadPass: "old", WritePass: "new", FriendlyName: "ambiguous"}); err == nil || out != nil {
		t.Fatal("multi-key rename accepted")
	}
	for _, input := range [][]byte{nil, data[:len(data)/2], append(append([]byte{}, data[:len(data)-1]...), data[len(data)-1]^1)} {
		if out, err := ChangePassword(input, "old", "new"); err == nil || out != nil {
			t.Fatal("invalid container accepted")
		}
	}
	if out, err := ChangePassword(data, "wrong", "new"); err == nil || out != nil {
		t.Fatal("wrong password accepted")
	}
	single := filepath.Join(dir, "single.p12")
	runComplexTool(t, tool, "single", single, "old")
	data, err = os.ReadFile(single)
	if err != nil {
		t.Fatal(err)
	}
	singleBefore := string(runComplexTool(t, tool, "snapshot", single, "old"))
	renamed, err := ChangePasswordWithOptions(data, &Options{ReadPass: "old", WritePass: "new", FriendlyName: "重命名"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(single, renamed, 0600); err != nil {
		t.Fatal(err)
	}
	after := string(runComplexTool(t, tool, "snapshot", single, "new"))
	expected := strings.ReplaceAll(singleBefore, "name=first key", "name=重命名")
	if after != expected || strings.Count(after, "name=重命名") != 2 {
		t.Fatalf("rename changed unrelated content\nbefore %s\nafter %s", singleBefore, after)
	}
}
