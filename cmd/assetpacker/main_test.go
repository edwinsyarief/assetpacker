package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIPackListVerify(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "assets")
	if err := os.MkdirAll(filepath.Join(srcDir, "sprites"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sprites", "hero.png"), []byte("png-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sprites", "hero.aseprite"), []byte("skip-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "config.json"), []byte(`{"hp":100}`), 0o644); err != nil {
		t.Fatal(err)
	}

	keyStr := "0123456789abcdef0123456789abcdef"
	outPak := filepath.Join(tmp, "out", "game.pak")

	// Test pack with -key-env
	t.Setenv("TEST_ASSET_KEY", keyStr)
	var stdout, stderr bytes.Buffer
	code := run([]string{"pack", "-src", srcDir, "-out", outPak, "-prefix", "game", "-key-env", "TEST_ASSET_KEY", "-v"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("pack failed with code %d: stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "aseprite") {
		t.Fatalf("excluded .aseprite file appeared in pack output: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "game/sprites/hero.png") {
		t.Fatalf("expected prefixed hero.png in output: %s", stdout.String())
	}

	// Test list with -key-file (including trailing newline)
	keyFile := filepath.Join(tmp, "key.txt")
	if err := os.WriteFile(keyFile, []byte(keyStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"list", "-in", outPak, "-key-file", keyFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("list failed with code %d: stderr=%s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 || lines[0] != "game/config.json" || lines[1] != "game/sprites/hero.png" {
		t.Fatalf("unexpected list output: %v", lines)
	}

	// Test verify with -key
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"verify", "-in", outPak, "-key", keyStr, "-v"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify failed with code %d: stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK: verified 2 assets") {
		t.Fatalf("unexpected verify output: %s", stdout.String())
	}

	// Corrupt a byte in the archive and verify fails
	raw, err := os.ReadFile(outPak)
	if err != nil {
		t.Fatal(err)
	}
	raw[20] ^= 0xff
	if err := os.WriteFile(outPak, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"verify", "-in", outPak, "-key", keyStr}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected verify to fail on corrupted archive")
	}
}
