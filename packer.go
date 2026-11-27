package assetpacker

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// tocEntry represents a single entry in the v2 encrypted table of contents.
type tocEntry struct {
	path       string
	assetType  string
	offset     uint64
	cipherSize uint64
	rawSize    uint64
	flags      uint8
}

// PackDirOption configures PackDir behavior.
type PackDirOption func(*packDirConfig)

type packDirConfig struct {
	excludes []string
	prefix   string
}

// WithExclude adds glob patterns to skip when walking a directory in PackDir.
// Patterns are matched against both the file/directory base name and its
// slash-normalized path relative to the source directory.
func WithExclude(patterns ...string) PackDirOption {
	return func(cfg *packDirConfig) {
		for _, p := range patterns {
			p = strings.TrimSpace(p)
			if p != "" {
				cfg.excludes = append(cfg.excludes, p)
			}
		}
	}
}

// WithPathPrefix prepends a virtual directory prefix to every packed asset path in PackDir.
func WithPathPrefix(prefix string) PackDirOption {
	return func(cfg *packDirConfig) {
		cfg.prefix = prefix
	}
}

// PackAssets compresses, encrypts, and atomically writes assets to outputPath using the v2 APAK format.
func PackAssets(assets []Asset, outputPath string, key []byte) error {
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	dir := filepath.Dir(outputPath)
	tmpFile, err := os.CreateTemp(dir, ".assetpacker-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	closed := false
	cleanup := func() {
		if !closed {
			_ = tmpFile.Close()
			closed = true
		}
		_ = os.Remove(tmpPath)
	}

	bw := bufio.NewWriterSize(tmpFile, 64*1024)
	if err := packAssetsToWriter(bw, assets, gcm); err != nil {
		cleanup()
		return err
	}
	if err := bw.Flush(); err != nil {
		cleanup()
		return fmt.Errorf("flush archive: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync archive: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		closed = true
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp archive: %w", err)
	}
	closed = true

	if err := os.Rename(tmpPath, outputPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename archive into place: %w", err)
	}

	return nil
}

// PackAssetsToBytes compresses and encrypts assets into an in-memory v2 APAK archive byte slice.
func PackAssetsToBytes(assets []Asset, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := packAssetsToWriter(&buf, assets, gcm); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PackDir recursively walks srcDir, skips hidden entries and configured exclude patterns,
// infers asset types by file extension, sorts paths deterministically, and writes a v2 archive to outputPath.
func PackDir(srcDir, outputPath string, key []byte, opts ...PackDirOption) error {
	info, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("stat source directory %q: %w", srcDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path %q is not a directory", srcDir)
	}

	var cfg packDirConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	var cleanPrefix string
	if cfg.prefix != "" {
		cleanPrefix, err = normalizePath(cfg.prefix)
		if err != nil {
			return fmt.Errorf("invalid path prefix %q: %w", cfg.prefix, err)
		}
	}

	for _, pat := range cfg.excludes {
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", pat, err)
		}
	}

	var assets []Asset
	err = filepath.WalkDir(srcDir, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fullPath == srcDir {
			return nil
		}

		name := d.Name()
		rel, err := filepath.Rel(srcDir, fullPath)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)

		if strings.HasPrefix(name, ".") || matchesAnyExclude(cfg.excludes, name, relSlash) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		virtualPath := relSlash
		if cleanPrefix != "" {
			virtualPath = path.Join(cleanPrefix, relSlash)
		}
		normPath, err := normalizePath(virtualPath)
		if err != nil {
			return err
		}

		assets = append(assets, Asset{
			Path:       normPath,
			Type:       inferAssetType(normPath),
			SourcePath: fullPath,
		})
		return nil
	})
	if err != nil {
		return err
	}

	slices.SortFunc(assets, func(a, b Asset) int {
		return strings.Compare(a.Path, b.Path)
	})

	return PackAssets(assets, outputPath, key)
}

func matchesAnyExclude(patterns []string, baseName, relSlash string) bool {
	for _, pat := range patterns {
		if ok, _ := path.Match(pat, baseName); ok {
			return true
		}
		if ok, _ := path.Match(pat, relSlash); ok {
			return true
		}
	}
	return false
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func packAssetsToWriter(w io.Writer, assets []Asset, gcm cipher.AEAD) error {
	var header [v2HeaderSize]byte
	copy(header[0:4], apakMagic[:])
	binary.LittleEndian.PutUint16(header[4:6], v2Version)
	binary.LittleEndian.PutUint16(header[6:8], v2Flags)

	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	currentOffset := uint64(v2HeaderSize)
	seen := make(map[string]struct{}, len(assets))
	entries := make([]tocEntry, 0, len(assets))

	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	var aadBuf [256]byte
	var cipherBuf []byte

	compBuf := getBuffer()
	defer putBuffer(compBuf)

	for _, asset := range assets {
		normPath, err := normalizePath(asset.Path)
		if err != nil {
			return err
		}
		if _, exists := seen[normPath]; exists {
			return fmt.Errorf("%w: %s", ErrDuplicatePath, normPath)
		}
		seen[normPath] = struct{}{}

		raw, err := resolveAssetContent(asset)
		if err != nil {
			return err
		}

		payload := raw
		var flags uint8
		if len(raw) > 0 && !shouldSkipCompression(normPath) {
			if err := compressGzipInto(compBuf, raw); err != nil {
				return fmt.Errorf("compress %s: %w", normPath, err)
			}
			if compBuf.Len() < len(raw) {
				payload = compBuf.Bytes()
				flags |= flagCompressed
			}
		}

		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("generate nonce for %s: %w", normPath, err)
		}

		rawSize := uint64(len(raw))
		aad := appendEntryAAD(aadBuf[:0], normPath, asset.Type, rawSize, flags)

		cipherBuf = append(cipherBuf[:0], nonce...)
		cipherBuf = gcm.Seal(cipherBuf, nonce, payload, aad)

		if _, err := w.Write(cipherBuf); err != nil {
			return fmt.Errorf("write payload for %s: %w", normPath, err)
		}

		cipherSize := uint64(len(cipherBuf))
		entries = append(entries, tocEntry{
			path:       normPath,
			assetType:  asset.Type,
			offset:     currentOffset,
			cipherSize: cipherSize,
			rawSize:    rawSize,
			flags:      flags,
		})
		currentOffset += cipherSize
	}

	tocPlain := encodeTOC(entries)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate TOC nonce: %w", err)
	}
	tocCipher := make([]byte, nonceSize, nonceSize+len(tocPlain)+gcm.Overhead())
	copy(tocCipher, nonce)
	tocCipher = gcm.Seal(tocCipher, nonce, tocPlain, tocAAD)

	if uint64(len(tocCipher)) > math.MaxUint32 {
		return fmt.Errorf("TOC ciphertext size %d exceeds uint32 limit", len(tocCipher))
	}

	tocOffset := currentOffset
	if _, err := w.Write(tocCipher); err != nil {
		return fmt.Errorf("write TOC: %w", err)
	}

	var trailer [v2TrailerSize]byte
	binary.LittleEndian.PutUint64(trailer[0:8], tocOffset)
	binary.LittleEndian.PutUint32(trailer[8:12], uint32(len(tocCipher)))
	copy(trailer[12:16], apakMagic[:])

	if _, err := w.Write(trailer[:]); err != nil {
		return fmt.Errorf("write trailer: %w", err)
	}

	return nil
}

func resolveAssetContent(asset Asset) ([]byte, error) {
	switch {
	case len(asset.Content) > 0:
		return asset.Content, nil
	case asset.SourcePath != "":
		content, err := os.ReadFile(asset.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", asset.SourcePath, err)
		}
		return content, nil
	case asset.Content != nil:
		return asset.Content, nil
	default:
		content, err := os.ReadFile(asset.Path)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", asset.Path, err)
		}
		return content, nil
	}
}

func encodeTOC(entries []tocEntry) []byte {
	// Estimate size to minimize reallocations.
	est := 4 + len(entries)*48
	buf := make([]byte, 0, est)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(entries)))

	for _, e := range entries {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(e.path)))
		buf = append(buf, e.path...)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(e.assetType)))
		buf = append(buf, e.assetType...)
		buf = binary.LittleEndian.AppendUint64(buf, e.offset)
		buf = binary.LittleEndian.AppendUint64(buf, e.cipherSize)
		buf = binary.LittleEndian.AppendUint64(buf, e.rawSize)
		buf = append(buf, e.flags)
	}
	return buf
}
