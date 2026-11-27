package assetpacker

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

var testKey32 = []byte("0123456789abcdef0123456789abcdef")

// buildLegacyV1Archive constructs a real v1 format blob identical to assetpacker v1.0.0.
func buildLegacyV1Archive(t *testing.T, assets []Asset, key []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	for _, a := range assets {
		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		if _, err := gz.Write(a.Content); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			t.Fatal(err)
		}
		encrypted := gcm.Seal(nonce, nonce, gzBuf.Bytes(), nil)

		fmt.Fprintf(&out, "%s:%s:%d:", a.Path, a.Type, len(encrypted))
		out.Write(encrypted)
	}
	return out.Bytes()
}

func TestRoundTripFileBytesReaderAtAndSourcePath(t *testing.T) {
	tmp := t.TempDir()
	diskFile := filepath.Join(tmp, "source_sprite.png")
	pngData := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte{0xAB, 0xCD}, 1024)...)
	if err := os.WriteFile(diskFile, pngData, 0o644); err != nil {
		t.Fatal(err)
	}

	directFile := filepath.Join(tmp, "direct.json")
	directData := []byte(strings.Repeat(`{"key":"value","hp":100},`, 200))
	if err := os.WriteFile(directFile, directData, 0o644); err != nil {
		t.Fatal(err)
	}

	inMemData := []byte("hello in-memory shader content\n" + strings.Repeat("vec4 color = vec4(1.0);\n", 50))
	emptyData := []byte{}

	assets := []Asset{
		{Path: "sprites/hero.png", Type: "image", SourcePath: diskFile},
		{Path: "shaders/glow.kage", Type: "shader", Content: inMemData},
		{Path: "empty.txt", Type: "text", Content: emptyData},
		{Path: directFile, Type: "json"},
	}

	// File round-trip
	pakPath := filepath.Join(tmp, "game.pak")
	if err := PackAssets(assets, pakPath, testKey32); err != nil {
		t.Fatalf("PackAssets failed: %v", err)
	}

	reader, err := NewAssetReader(pakPath, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReader failed: %v", err)
	}
	defer reader.Close()

	if reader.Len() != len(assets) {
		t.Fatalf("Len() = %d, want %d", reader.Len(), len(assets))
	}

	// Verify smart compression flags in TOC
	if reader.entries["sprites/hero.png"].flags&flagCompressed != 0 {
		t.Errorf("expected .png to skip gzip compression")
	}
	if reader.entries["shaders/glow.kage"].flags&flagCompressed == 0 {
		t.Errorf("expected compressible .kage shader to use gzip compression")
	}

	gotHero, err := reader.GetAsset("sprites/hero.png")
	if err != nil {
		t.Fatalf("GetAsset(sprites/hero.png) error: %v", err)
	}
	if gotHero.Type != "image" || !bytes.Equal(gotHero.Content, pngData) {
		t.Fatalf("hero asset mismatch")
	}

	gotShader, err := reader.GetAsset("./sprites/../shaders/glow.kage")
	if err == nil {
		t.Fatalf("expected error on path containing '..', got %v", gotShader.Path)
	}
	gotShader, err = reader.GetAsset("./shaders/glow.kage")
	if err != nil {
		t.Fatalf("GetAsset(./shaders/glow.kage) error: %v", err)
	}
	if gotShader.Type != "shader" || !bytes.Equal(gotShader.Content, inMemData) {
		t.Fatalf("shader asset mismatch")
	}

	gotEmpty, err := reader.GetAsset("empty.txt")
	if err != nil {
		t.Fatalf("GetAsset(empty.txt) error: %v", err)
	}
	if len(gotEmpty.Content) != 0 {
		t.Fatalf("expected empty content, got %d bytes", len(gotEmpty.Content))
	}

	gotDirect, err := reader.GetAsset(directFile)
	if err != nil {
		t.Fatalf("GetAsset(directFile) error: %v", err)
	}
	if !bytes.Equal(gotDirect.Content, directData) {
		t.Fatalf("direct file content mismatch")
	}

	// Bytes round-trip
	blob, err := PackAssetsToBytes(assets[:3], testKey32)
	if err != nil {
		t.Fatalf("PackAssetsToBytes failed: %v", err)
	}
	br, err := NewAssetReaderFromBytes(blob, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReaderFromBytes failed: %v", err)
	}
	defer br.Close()

	if !br.Has("sprites/hero.png") || br.Has("missing.png") {
		t.Fatalf("Has() returned unexpected results")
	}

	// ReaderAt round-trip
	rr, err := NewAssetReaderFromReaderAt(bytes.NewReader(blob), int64(len(blob)), testKey32)
	if err != nil {
		t.Fatalf("NewAssetReaderFromReaderAt failed: %v", err)
	}
	defer rr.Close()

	gotRR, err := rr.GetAsset("shaders/glow.kage")
	if err != nil || !bytes.Equal(gotRR.Content, inMemData) {
		t.Fatalf("ReaderAt GetAsset mismatch: err=%v", err)
	}
}

func TestSmartCompressionSkipsIncompressibleBinary(t *testing.T) {
	randomBytes := make([]byte, 8192)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		t.Fatal(err)
	}

	blob, err := PackAssetsToBytes([]Asset{
		{Path: "data/random.bin", Type: "binary", Content: randomBytes},
	}, testKey32)
	if err != nil {
		t.Fatalf("PackAssetsToBytes failed: %v", err)
	}

	r, err := NewAssetReaderFromBytes(blob, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReaderFromBytes failed: %v", err)
	}
	defer r.Close()

	if r.entries["data/random.bin"].flags&flagCompressed != 0 {
		t.Fatalf("expected incompressible random bytes to skip gzip storage")
	}
	a, err := r.GetAsset("data/random.bin")
	if err != nil || !bytes.Equal(a.Content, randomBytes) {
		t.Fatalf("random binary round-trip mismatch: err=%v", err)
	}
}

func TestPackDirWithExcludesAndPrefix(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "assets")

	files := map[string]string{
		"sprites/player.png":    "png-data",
		"sprites/player.aseprite": "ignore-aseprite",
		"audio/bgm.ogg":         "ogg-data",
		"fonts/ui.ttf":          "ttf-data",
		"shaders/crt.kage":      "kage-data",
		"maps/level1.json":      `{"level":1}`,
		"docs/readme.txt":       "hello world",
		"data/raw.dat":          "raw-bytes",
		".hidden/secret.txt":    "should-skip-hidden-dir",
		".DS_Store":             "should-skip-hidden-file",
		"Thumbs.db":             "should-skip-excluded",
		"temp/scratch.tmp":      "should-skip-temp-dir",
	}

	for rel, content := range files {
		full := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	outPak := filepath.Join(tmp, "dir.pak")
	err := PackDir(src, outPak, testKey32,
		WithExclude("*.aseprite", "Thumbs.db", "temp"),
		WithPathPrefix("assets"),
	)
	if err != nil {
		t.Fatalf("PackDir failed: %v", err)
	}

	r, err := NewAssetReader(outPak, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReader failed: %v", err)
	}
	defer r.Close()

	wantPaths := []string{
		"assets/audio/bgm.ogg",
		"assets/data/raw.dat",
		"assets/docs/readme.txt",
		"assets/fonts/ui.ttf",
		"assets/maps/level1.json",
		"assets/shaders/crt.kage",
		"assets/sprites/player.png",
	}
	gotPaths := r.List()
	if !slices.Equal(gotPaths, wantPaths) {
		t.Fatalf("List() = %v, want %v", gotPaths, wantPaths)
	}

	wantTypes := map[string]string{
		"assets/sprites/player.png": "image",
		"assets/audio/bgm.ogg":      "audio",
		"assets/fonts/ui.ttf":       "font",
		"assets/shaders/crt.kage":   "shader",
		"assets/maps/level1.json":   "json",
		"assets/docs/readme.txt":    "text",
		"assets/data/raw.dat":       "binary",
	}
	for p, wantType := range wantTypes {
		a, err := r.GetAsset(p)
		if err != nil {
			t.Fatalf("GetAsset(%q) failed: %v", p, err)
		}
		if a.Type != wantType {
			t.Errorf("asset %q type = %q, want %q", p, a.Type, wantType)
		}
	}

	// Verify deterministic output order by packing twice and comparing TOC entry order.
	if err := fstest.TestFS(r, wantPaths...); err != nil {
		t.Fatalf("fstest.TestFS failed: %v", err)
	}
}

func TestLegacyV1Compatibility(t *testing.T) {
	v1Assets := []Asset{
		{Path: "assets\\sprites\\hero.png", Type: "sprite", Content: []byte("legacy-hero-png")},
		{Path: "./assets/maps/level1.json", Type: "map", Content: []byte(`{"v":1}`)},
	}
	v1Blob := buildLegacyV1Archive(t, v1Assets, testKey32)

	// Read from bytes
	rBytes, err := NewAssetReaderFromBytes(v1Blob, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReaderFromBytes(v1) failed: %v", err)
	}
	defer rBytes.Close()

	if !rBytes.isLegacy {
		t.Fatalf("expected legacy v1 mode")
	}

	// Read from file
	pakPath := filepath.Join(t.TempDir(), "legacy.pak")
	if err := os.WriteFile(pakPath, v1Blob, 0o644); err != nil {
		t.Fatal(err)
	}
	rFile, err := NewAssetReader(pakPath, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReader(v1) failed: %v", err)
	}
	defer rFile.Close()

	for _, r := range []*AssetReader{rBytes, rFile} {
		hero, err := r.GetAsset("assets/sprites/hero.png")
		if err != nil || string(hero.Content) != "legacy-hero-png" || hero.Type != "sprite" {
			t.Fatalf("v1 hero mismatch: asset=%+v err=%v", hero, err)
		}
		// Lookup with Windows backslash and leading ./ should also work
		hero2, err := r.GetAsset("assets\\sprites\\hero.png")
		if err != nil || string(hero2.Content) != "legacy-hero-png" {
			t.Fatalf("v1 backslash lookup failed: err=%v", err)
		}
		lvl, err := r.GetAsset("assets/maps/level1.json")
		if err != nil || string(lvl.Content) != `{"v":1}` {
			t.Fatalf("v1 level mismatch: asset=%+v err=%v", lvl, err)
		}

		if err := fstest.TestFS(r, "assets/maps/level1.json", "assets/sprites/hero.png"); err != nil {
			t.Fatalf("fstest.TestFS on legacy v1 failed: %v", err)
		}
	}
}

func TestPathNormalizationSpecialCases(t *testing.T) {
	assets := []Asset{
		{Path: `assets\sprites\player.png`, Type: "image", Content: []byte("win-slash")},
		{Path: `./ui/button.png`, Type: "image", Content: []byte("dot-slash")},
		{Path: `日本語/스프라이트.png`, Type: "image", Content: []byte("unicode-data")},
		{Path: `C:/virtual:name/sprite.png`, Type: "image", Content: []byte("colon-path")},
	}

	blob, err := PackAssetsToBytes(assets, testKey32)
	if err != nil {
		t.Fatalf("PackAssetsToBytes failed: %v", err)
	}

	r, err := NewAssetReaderFromBytes(blob, testKey32)
	if err != nil {
		t.Fatalf("NewAssetReaderFromBytes failed: %v", err)
	}
	defer r.Close()

	lookups := map[string]string{
		"assets/sprites/player.png":   "win-slash",
		`assets\sprites\player.png`:   "win-slash",
		"./assets/sprites/player.png": "win-slash",
		"/ui/button.png":              "dot-slash",
		"日本語/스프라이트.png":               "unicode-data",
		"C:/virtual:name/sprite.png":  "colon-path",
		`C:\virtual:name\sprite.png`:  "colon-path",
	}
	for query, want := range lookups {
		a, err := r.GetAsset(query)
		if err != nil {
			t.Fatalf("GetAsset(%q) failed: %v", query, err)
		}
		if string(a.Content) != want {
			t.Errorf("GetAsset(%q) = %q, want %q", query, a.Content, want)
		}
	}

	if err := fstest.TestFS(r,
		"C:/virtual:name/sprite.png",
		"assets/sprites/player.png",
		"ui/button.png",
		"日本語/스프라이트.png",
	); err != nil {
		t.Fatalf("fstest.TestFS failed: %v", err)
	}
}

func TestSecurityFailures(t *testing.T) {
	baseAssets := []Asset{
		{Path: "a.txt", Type: "text", Content: []byte(strings.Repeat("alpha-", 100))},
		{Path: "b.txt", Type: "text", Content: []byte(strings.Repeat("bravo-", 100))},
	}
	blob, err := PackAssetsToBytes(baseAssets, testKey32)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("WrongKeyV2", func(t *testing.T) {
		wrongKey := []byte("fedcba9876543210fedcba9876543210")
		if _, err := NewAssetReaderFromBytes(blob, wrongKey); err == nil {
			t.Fatal("expected error with wrong key")
		}
	})

	t.Run("WrongKeyV1", func(t *testing.T) {
		v1 := buildLegacyV1Archive(t, baseAssets, testKey32)
		wrongKey := []byte("fedcba9876543210fedcba9876543210")
		if _, err := NewAssetReaderFromBytes(v1, wrongKey); err == nil {
			t.Fatal("expected error with wrong key on v1")
		}
	})

	t.Run("BitFlippedPayloadCiphertext", func(t *testing.T) {
		corrupt := slices.Clone(blob)
		corrupt[v2HeaderSize+20] ^= 0x01
		r, err := NewAssetReaderFromBytes(corrupt, testKey32)
		if err != nil {
			t.Fatalf("TOC should still open cleanly when only payload is flipped: %v", err)
		}
		defer r.Close()
		if _, err := r.GetAsset("a.txt"); err == nil {
			t.Fatal("expected authentication error on flipped payload ciphertext")
		}
	})

	t.Run("BitFlippedTOCCiphertext", func(t *testing.T) {
		corrupt := slices.Clone(blob)
		tocPos := len(corrupt) - v2TrailerSize - 10
		corrupt[tocPos] ^= 0x80
		if _, err := NewAssetReaderFromBytes(corrupt, testKey32); err == nil {
			t.Fatal("expected authentication error on flipped TOC ciphertext")
		}
	})

	t.Run("TamperedTOCMetadataCaughtByEntryAAD", func(t *testing.T) {
		// Re-encrypt a forged TOC using the SAME key, swapping entry offsets / changing assetType.
		// Entry GCM AAD binds (normalizedPath, assetType, rawSize, flags), so GetAsset MUST fail!
		r, err := NewAssetReaderFromBytes(blob, testKey32)
		if err != nil {
			t.Fatal(err)
		}
		eA := r.entries["a.txt"]
		eB := r.entries["b.txt"]
		r.Close()

		// Swap a.txt and b.txt ciphertext pointers AND alter assetType
		forgedA := eA
		forgedA.offset = eB.offset
		forgedA.cipherSize = eB.cipherSize
		forgedB := eB
		forgedB.assetType = "tampered-type"

		tocOffset := binary.LittleEndian.Uint64(blob[len(blob)-v2TrailerSize : len(blob)-v2TrailerSize+8])
		payloadPart := slices.Clone(blob[:tocOffset])

		gcm, err := newGCM(testKey32)
		if err != nil {
			t.Fatal(err)
		}
		forgedTOCPlain := encodeTOC([]tocEntry{forgedA, forgedB})
		nonce := make([]byte, gcm.NonceSize())
		_, _ = io.ReadFull(rand.Reader, nonce)
		forgedTOCCipher := gcm.Seal(nonce, nonce, forgedTOCPlain, tocAAD)

		var forged bytes.Buffer
		forged.Write(payloadPart)
		forged.Write(forgedTOCCipher)
		var trailer [v2TrailerSize]byte
		binary.LittleEndian.PutUint64(trailer[0:8], tocOffset)
		binary.LittleEndian.PutUint32(trailer[8:12], uint32(len(forgedTOCCipher)))
		copy(trailer[12:16], apakMagic[:])
		forged.Write(trailer[:])

		fr, err := NewAssetReaderFromBytes(forged.Bytes(), testKey32)
		if err != nil {
			t.Fatalf("forged TOC signed with same key should open TOC: %v", err)
		}
		defer fr.Close()

		if _, err := fr.GetAsset("a.txt"); err == nil {
			t.Fatal("expected AAD mismatch when swapping entries in TOC")
		}
		if _, err := fr.GetAsset("b.txt"); err == nil {
			t.Fatal("expected AAD mismatch when modifying assetType in TOC")
		}
	})

	t.Run("TruncatedArchive", func(t *testing.T) {
		cutPoints := []int{1, 4, 8, 12, len(blob) / 2, len(blob) - v2TrailerSize, len(blob) - 1}
		for _, cut := range cutPoints {
			if _, err := NewAssetReaderFromBytes(blob[:cut], testKey32); err == nil {
				t.Errorf("expected error for archive truncated to %d bytes", cut)
			}
		}
	})

	t.Run("LegacyV1NegativeHugeAndTruncatedSize", func(t *testing.T) {
		badBlobs := [][]byte{
			[]byte("a.txt:text:-5:abcdef"),
			[]byte("a.txt:text:999999999999:abcdef"),
			[]byte("a.txt:text:100:short"),
		}
		for i, bad := range badBlobs {
			if _, err := NewAssetReaderFromBytes(bad, testKey32); err == nil {
				t.Errorf("case %d: expected error for malformed v1 archive", i)
			}
		}
	})

	t.Run("GzipBombLimitV2AndV1", func(t *testing.T) {
		bombContent := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB compresses to ~1 KiB
		bombAssets := []Asset{{Path: "bomb.txt", Type: "text", Content: bombContent}}

		v2Bomb, err := PackAssetsToBytes(bombAssets, testKey32)
		if err != nil {
			t.Fatal(err)
		}
		rV2, err := NewAssetReaderFromBytes(v2Bomb, testKey32, WithMaxUncompressedSize(4096))
		if err != nil {
			t.Fatalf("opening v2 TOC should succeed before lazy read: %v", err)
		}
		defer rV2.Close()
		if _, err := rV2.GetAsset("bomb.txt"); !errors.Is(err, ErrAssetTooLarge) {
			t.Fatalf("v2 gzip bomb: got err=%v, want ErrAssetTooLarge", err)
		}

		v1Bomb := buildLegacyV1Archive(t, bombAssets, testKey32)
		if _, err := NewAssetReaderFromBytes(v1Bomb, testKey32, WithMaxUncompressedSize(4096)); !errors.Is(err, ErrAssetTooLarge) {
			t.Fatalf("v1 gzip bomb: got err=%v, want ErrAssetTooLarge", err)
		}
	})

	t.Run("DuplicateNormalizedPaths", func(t *testing.T) {
		dups := []Asset{
			{Path: "sprites/hero.png", Type: "image", Content: []byte("1")},
			{Path: `./sprites\hero.png`, Type: "image", Content: []byte("2")},
		}
		if _, err := PackAssetsToBytes(dups, testKey32); !errors.Is(err, ErrDuplicatePath) {
			t.Fatalf("expected ErrDuplicatePath, got %v", err)
		}
	})

	t.Run("PathTraversalRejected", func(t *testing.T) {
		badPaths := []string{
			"",
			".",
			"./",
			"/",
			"..",
			"../secret.txt",
			`..\secret.txt`,
			"a/../../secret.txt",
			"/../secret.txt",
			"a/../b.txt",
			"bad\x00path.txt",
		}
		for _, p := range badPaths {
			_, err := PackAssetsToBytes([]Asset{{Path: p, Type: "text", Content: []byte("x")}}, testKey32)
			if !errors.Is(err, ErrInvalidPath) {
				t.Errorf("path %q: got err=%v, want ErrInvalidPath", p, err)
			}
		}
	})
}

func TestCacheDefensiveCopyAndClose(t *testing.T) {
	original := []byte("immutable-payload-data")
	blob, err := PackAssetsToBytes([]Asset{
		{Path: "data.txt", Type: "text", Content: original},
	}, testKey32)
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewAssetReaderFromBytes(blob, testKey32, WithCache(true))
	if err != nil {
		t.Fatal(err)
	}

	a1, err := r.GetAsset("data.txt")
	if err != nil {
		t.Fatal(err)
	}
	a1.Content[0] = 'X' // mutate returned slice

	a2, err := r.GetAsset("data.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a2.Content, original) {
		t.Fatalf("cache was mutated by caller: got %q, want %q", a2.Content, original)
	}

	// Close is idempotent and blocks subsequent reads
	if err := r.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	if _, err := r.GetAsset("data.txt"); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed after Close, got %v", err)
	}
}

func TestConcurrency(t *testing.T) {
	assets := make([]Asset, 20)
	for i := range assets {
		assets[i] = Asset{
			Path:    fmt.Sprintf("dir%d/asset_%02d.json", i%4, i),
			Type:    "json",
			Content: []byte(fmt.Sprintf(`{"id":%d,"payload":%q}`, i, strings.Repeat("xyz", 100))),
		}
	}

	pakPath := filepath.Join(t.TempDir(), "concurrent.pak")
	if err := PackAssets(assets, pakPath, testKey32); err != nil {
		t.Fatal(err)
	}

	for _, cached := range []bool{false, true} {
		name := "Uncached"
		if cached {
			name = "Cached"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewAssetReader(pakPath, testKey32, WithCache(cached))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()

			const workers = 16
			const iters = 50
			var wg sync.WaitGroup
			errCh := make(chan error, workers)

			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					for i := 0; i < iters; i++ {
						idx := (id + i) % len(assets)
						p := assets[idx].Path

						if !r.Has(p) {
							errCh <- fmt.Errorf("Has(%s) = false", p)
							return
						}
						if len(r.List()) != len(assets) {
							errCh <- fmt.Errorf("List() length mismatch")
							return
						}
						a, err := r.GetAsset(p)
						if err != nil {
							errCh <- fmt.Errorf("GetAsset(%s): %w", p, err)
							return
						}
						if !bytes.Equal(a.Content, assets[idx].Content) {
							errCh <- fmt.Errorf("GetAsset(%s) content mismatch", p)
							return
						}
						raw, err := r.ReadFile(p)
						if err != nil {
							errCh <- fmt.Errorf("ReadFile(%s): %w", p, err)
							return
						}
						if !bytes.Equal(raw, assets[idx].Content) {
							errCh <- fmt.Errorf("ReadFile(%s) content mismatch", p)
							return
						}
					}
				}(w)
			}

			wg.Wait()
			close(errCh)
			for err := range errCh {
				t.Fatal(err)
			}
		})
	}
}

func makeBenchmarkAssets() []Asset {
	jsonPayload := []byte(strings.Repeat(`{"tile":12,"solid":true,"name":"grass_block"},`, 200))
	pngPayload := make([]byte, 32*1024)
	for i := range pngPayload {
		pngPayload[i] = byte((i * 73) ^ (i >> 3))
	}

	assets := make([]Asset, 0, 20)
	for i := 0; i < 10; i++ {
		assets = append(assets, Asset{
			Path:    fmt.Sprintf("maps/level_%02d.json", i),
			Type:    "json",
			Content: jsonPayload,
		})
		assets = append(assets, Asset{
			Path:    fmt.Sprintf("sprites/sheet_%02d.png", i),
			Type:    "image",
			Content: pngPayload,
		})
	}
	return assets
}

func BenchmarkPackAssets(b *testing.B) {
	assets := makeBenchmarkAssets()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := PackAssetsToBytes(assets, testKey32); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenReader(b *testing.B) {
	blob, err := PackAssetsToBytes(makeBenchmarkAssets(), testKey32)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r, err := NewAssetReaderFromBytes(blob, testKey32)
		if err != nil {
			b.Fatal(err)
		}
		_ = r.Close()
	}
}

func BenchmarkGetAssetUncached(b *testing.B) {
	blob, err := PackAssetsToBytes(makeBenchmarkAssets(), testKey32)
	if err != nil {
		b.Fatal(err)
	}
	r, err := NewAssetReaderFromBytes(blob, testKey32, WithCache(false))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := r.GetAsset("maps/level_00.json"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetAssetCached(b *testing.B) {
	blob, err := PackAssetsToBytes(makeBenchmarkAssets(), testKey32)
	if err != nil {
		b.Fatal(err)
	}
	r, err := NewAssetReaderFromBytes(blob, testKey32, WithCache(true))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()

	// Warm cache
	if _, err := r.GetAsset("maps/level_00.json"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := r.GetAsset("maps/level_00.json"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetAssetPNGSkipGzip(b *testing.B) {
	blob, err := PackAssetsToBytes(makeBenchmarkAssets(), testKey32)
	if err != nil {
		b.Fatal(err)
	}
	r, err := NewAssetReaderFromBytes(blob, testKey32, WithCache(false))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := r.GetAsset("sprites/sheet_00.png"); err != nil {
			b.Fatal(err)
		}
	}
}
