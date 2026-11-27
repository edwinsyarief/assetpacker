package assetpacker

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"sync"
)

// ReaderOption configures an AssetReader.
type ReaderOption func(*readerConfig)

type readerConfig struct {
	cacheEnabled        bool
	maxUncompressedSize int64
}

// WithCache enables or disables in-memory caching of decrypted assets for v2 archives.
// When enabled, decrypted assets are cached in memory after their first read and
// subsequent reads return a defensive copy. Defaults to false for low memory usage.
// Legacy v1 archives always load assets into memory because v1 has no table of contents.
func WithCache(enabled bool) ReaderOption {
	return func(cfg *readerConfig) {
		cfg.cacheEnabled = enabled
	}
}

// WithMaxUncompressedSize configures the maximum allowed uncompressed byte size for a single asset.
// Defaults to 256 MiB (256 << 20). Protects against gzip decompression bombs.
func WithMaxUncompressedSize(limit int64) ReaderOption {
	return func(cfg *readerConfig) {
		cfg.maxUncompressedSize = limit
	}
}

// AssetReader reads and decrypts assets from a v2 APAK archive (lazily on demand)
// or a legacy v1 archive. It is safe for concurrent use by multiple goroutines.
type AssetReader struct {
	mu                  sync.RWMutex
	readerAt            io.ReaderAt
	closer              io.Closer
	size                int64
	gcm                 cipher.AEAD
	isLegacy            bool
	closed              bool
	cacheEnabled        bool
	maxUncompressedSize int64

	entries map[string]tocEntry
	paths   []string
	dirs    map[string][]string
	dirSet  map[string]struct{}
	cache   map[string][]byte
}

// NewAssetReader opens an encrypted asset archive file and validates its table of contents.
// For v2 archives, individual asset payloads are read and decrypted lazily on demand.
// Call Close when finished to release the underlying file handle.
func NewAssetReader(filePath string, key []byte, opts ...ReaderOption) (*AssetReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	ar, err := newAssetReaderFromReaderAt(file, info.Size(), key, file, opts...)
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	// Legacy v1 archives are fully decrypted into memory on open; close the file immediately.
	if ar.isLegacy {
		ar.closer = nil
		if err := file.Close(); err != nil {
			return nil, err
		}
	}

	return ar, nil
}

// NewAssetReaderFromBytes initializes an AssetReader from an in-memory archive byte slice.
func NewAssetReaderFromBytes(data []byte, key []byte, opts ...ReaderOption) (*AssetReader, error) {
	return NewAssetReaderFromReaderAt(bytes.NewReader(data), int64(len(data)), key, opts...)
}

// NewAssetReaderFromReaderAt initializes an AssetReader from any io.ReaderAt and known byte size.
func NewAssetReaderFromReaderAt(r io.ReaderAt, size int64, key []byte, opts ...ReaderOption) (*AssetReader, error) {
	return newAssetReaderFromReaderAt(r, size, key, nil, opts...)
}

func newAssetReaderFromReaderAt(r io.ReaderAt, size int64, key []byte, closer io.Closer, opts ...ReaderOption) (*AssetReader, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalidArchive)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: negative archive size %d", ErrInvalidArchive, size)
	}

	cfg := readerConfig{
		cacheEnabled:        false,
		maxUncompressedSize: defaultMaxUncompressedSize,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.maxUncompressedSize <= 0 {
		return nil, fmt.Errorf("%w: max uncompressed size must be positive", ErrInvalidArchive)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	ar := &AssetReader{
		readerAt:            r,
		closer:              closer,
		size:                size,
		gcm:                 gcm,
		cacheEnabled:        cfg.cacheEnabled,
		maxUncompressedSize: cfg.maxUncompressedSize,
	}

	if size >= v2HeaderSize {
		var hdr [v2HeaderSize]byte
		if _, err := readFullAt(r, hdr[:], 0); err != nil {
			return nil, fmt.Errorf("%w: read header: %v", ErrInvalidArchive, err)
		}

		if bytes.Equal(hdr[0:4], apakMagic[:]) {
			version := binary.LittleEndian.Uint16(hdr[4:6])
			flags := binary.LittleEndian.Uint16(hdr[6:8])

			if version == v2Version {
				if flags != v2Flags {
					return nil, fmt.Errorf("%w: unsupported v2 flags %d", ErrUnsupportedVersion, flags)
				}
				if err := ar.loadV2(); err != nil {
					return nil, err
				}
				return ar, nil
			}

			// If trailer also ends with APAK magic, this is an unsupported APAK version.
			if size >= v2MinSize {
				var trailerMagic [4]byte
				if _, err := readFullAt(r, trailerMagic[:], size-4); err == nil && bytes.Equal(trailerMagic[:], apakMagic[:]) {
					return nil, fmt.Errorf("%w: version %d", ErrUnsupportedVersion, version)
				}
			}
		}
	}

	if err := ar.loadLegacyV1(); err != nil {
		return nil, err
	}
	return ar, nil
}

func (ar *AssetReader) loadV2() error {
	if ar.size < v2MinSize {
		return fmt.Errorf("%w: v2 archive too small (%d bytes)", ErrInvalidArchive, ar.size)
	}

	var trailer [v2TrailerSize]byte
	if _, err := readFullAt(ar.readerAt, trailer[:], ar.size-v2TrailerSize); err != nil {
		return fmt.Errorf("%w: read trailer: %v", ErrInvalidArchive, err)
	}
	if !bytes.Equal(trailer[12:16], apakMagic[:]) {
		return fmt.Errorf("%w: invalid v2 trailer magic", ErrInvalidArchive)
	}

	tocOffset := binary.LittleEndian.Uint64(trailer[0:8])
	tocCipherLen := binary.LittleEndian.Uint32(trailer[8:12])

	minCipherLen := uint64(ar.gcm.NonceSize() + ar.gcm.Overhead())
	tocEnd := uint64(ar.size - v2TrailerSize)

	if tocOffset < v2HeaderSize || tocOffset > tocEnd {
		return fmt.Errorf("%w: invalid TOC offset %d", ErrInvalidArchive, tocOffset)
	}
	if uint64(tocCipherLen) < minCipherLen || uint64(tocCipherLen) != tocEnd-tocOffset {
		return fmt.Errorf("%w: invalid TOC length %d", ErrInvalidArchive, tocCipherLen)
	}

	tocCipher := make([]byte, tocCipherLen)
	if _, err := readFullAt(ar.readerAt, tocCipher, int64(tocOffset)); err != nil {
		return fmt.Errorf("%w: read TOC: %v", ErrInvalidArchive, err)
	}

	nonceSize := ar.gcm.NonceSize()
	ciphertext := tocCipher[nonceSize:]
	tocPlain, err := ar.gcm.Open(ciphertext[:0], tocCipher[:nonceSize], ciphertext, tocAAD)
	if err != nil {
		return fmt.Errorf("%w: decrypt TOC: %v", ErrInvalidArchive, err)
	}

	entries, paths, err := decodeTOC(tocPlain, tocOffset, minCipherLen)
	if err != nil {
		return err
	}

	ar.entries = entries
	ar.paths = paths
	if ar.cacheEnabled {
		ar.cache = make(map[string][]byte, len(entries))
	}
	ar.buildDirIndex()
	return nil
}

func decodeTOC(data []byte, tocOffset, minCipherLen uint64) (map[string]tocEntry, []string, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("%w: truncated TOC count", ErrInvalidArchive)
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	rem := data[4:]

	// Minimum serialized entry size is 4+4+8+8+8+1 = 33 bytes.
	if uint64(count)*33 > uint64(len(rem)) {
		return nil, nil, fmt.Errorf("%w: invalid TOC entry count %d", ErrInvalidArchive, count)
	}

	entries := make(map[string]tocEntry, count)
	paths := make([]string, 0, count)

	for i := uint32(0); i < count; i++ {
		if len(rem) < 4 {
			return nil, nil, fmt.Errorf("%w: truncated TOC path length", ErrInvalidArchive)
		}
		pathLen := binary.LittleEndian.Uint32(rem[0:4])
		rem = rem[4:]
		if uint64(pathLen) > uint64(len(rem)) {
			return nil, nil, fmt.Errorf("%w: truncated TOC path", ErrInvalidArchive)
		}
		rawPath := string(rem[:pathLen])
		rem = rem[pathLen:]

		if len(rem) < 4 {
			return nil, nil, fmt.Errorf("%w: truncated TOC type length", ErrInvalidArchive)
		}
		typeLen := binary.LittleEndian.Uint32(rem[0:4])
		rem = rem[4:]
		if uint64(typeLen) > uint64(len(rem)) {
			return nil, nil, fmt.Errorf("%w: truncated TOC type", ErrInvalidArchive)
		}
		assetType := string(rem[:typeLen])
		rem = rem[typeLen:]

		if len(rem) < 25 {
			return nil, nil, fmt.Errorf("%w: truncated TOC entry metadata", ErrInvalidArchive)
		}
		offset := binary.LittleEndian.Uint64(rem[0:8])
		cipherSize := binary.LittleEndian.Uint64(rem[8:16])
		rawSize := binary.LittleEndian.Uint64(rem[16:24])
		flags := rem[24]
		rem = rem[25:]

		if flags&^flagCompressed != 0 {
			return nil, nil, fmt.Errorf("%w: unsupported entry flags %d for %q", ErrUnsupportedVersion, flags, rawPath)
		}

		normPath, err := normalizePath(rawPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		if _, dup := entries[normPath]; dup {
			return nil, nil, fmt.Errorf("%w: %s", ErrDuplicatePath, normPath)
		}

		if offset < v2HeaderSize || offset > tocOffset {
			return nil, nil, fmt.Errorf("%w: invalid entry offset for %q", ErrInvalidArchive, normPath)
		}
		if cipherSize < minCipherLen || cipherSize > tocOffset-offset {
			return nil, nil, fmt.Errorf("%w: invalid entry size for %q", ErrInvalidArchive, normPath)
		}

		entries[normPath] = tocEntry{
			path:       normPath,
			assetType:  assetType,
			offset:     offset,
			cipherSize: cipherSize,
			rawSize:    rawSize,
			flags:      flags,
		}
		paths = append(paths, normPath)
	}

	if len(rem) != 0 {
		return nil, nil, fmt.Errorf("%w: trailing %d bytes in TOC", ErrInvalidArchive, len(rem))
	}

	slices.Sort(paths)
	return entries, paths, nil
}

func (ar *AssetReader) loadLegacyV1() error {
	ar.isLegacy = true

	sr := io.NewSectionReader(ar.readerAt, 0, ar.size)
	br := bufio.NewReader(sr)

	entries := make(map[string]tocEntry)
	cache := make(map[string][]byte)
	var paths []string

	nonceSize := ar.gcm.NonceSize()
	minCipherLen := int64(nonceSize + ar.gcm.Overhead())
	var consumed int64

	for {
		rawPath, n, err := readUntilColonLimited(br, maxV1HeaderFieldLen)
		consumed += n
		if err != nil {
			if errors.Is(err, io.EOF) && n == 0 {
				break
			}
			return fmt.Errorf("%w: read v1 path: %v", ErrInvalidArchive, err)
		}

		assetType, n, err := readUntilColonLimited(br, maxV1HeaderFieldLen)
		consumed += n
		if err != nil {
			return fmt.Errorf("%w: read v1 type for %q: %v", ErrInvalidArchive, rawPath, err)
		}

		sizeStr, n, err := readUntilColonLimited(br, 32)
		consumed += n
		if err != nil {
			return fmt.Errorf("%w: read v1 size for %q: %v", ErrInvalidArchive, rawPath, err)
		}

		sizeInt, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: invalid v1 size %q for %q: %v", ErrInvalidArchive, sizeStr, rawPath, err)
		}
		remaining := ar.size - consumed
		if sizeInt < minCipherLen || sizeInt > remaining {
			return fmt.Errorf("%w: out-of-range v1 payload size %d (remaining %d) for %q", ErrInvalidArchive, sizeInt, remaining, rawPath)
		}
		if sizeInt > ar.maxUncompressedSize+(1<<20) {
			return fmt.Errorf("%w: v1 encrypted size %d exceeds limit for %q", ErrAssetTooLarge, sizeInt, rawPath)
		}

		normPath, err := normalizePath(rawPath)
		if err != nil {
			return err
		}
		if _, dup := entries[normPath]; dup {
			return fmt.Errorf("%w: %s", ErrDuplicatePath, normPath)
		}

		encrypted := make([]byte, sizeInt)
		if _, err := io.ReadFull(br, encrypted); err != nil {
			return fmt.Errorf("%w: read v1 payload for %q: %v", ErrInvalidArchive, normPath, err)
		}
		consumed += sizeInt

		ciphertext := encrypted[nonceSize:]
		decrypted, err := ar.gcm.Open(ciphertext[:0], encrypted[:nonceSize], ciphertext, nil)
		if err != nil {
			return fmt.Errorf("%w: decrypt v1 payload for %q: %v", ErrInvalidArchive, normPath, err)
		}

		content, err := decompressGzipBounded(decrypted, ar.maxUncompressedSize)
		if err != nil {
			return fmt.Errorf("decompress v1 payload for %q: %w", normPath, err)
		}

		entries[normPath] = tocEntry{
			path:      normPath,
			assetType: assetType,
			rawSize:   uint64(len(content)),
			flags:     flagCompressed,
		}
		cache[normPath] = content
		paths = append(paths, normPath)
	}

	slices.Sort(paths)
	ar.entries = entries
	ar.paths = paths
	ar.cache = cache
	ar.buildDirIndex()
	return nil
}

func readUntilColonLimited(r *bufio.Reader, maxLen int) (string, int64, error) {
	var buf []byte
	var n int64
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", n, err
		}
		n++
		if b == ':' {
			return string(buf), n, nil
		}
		if len(buf) >= maxLen {
			return "", n, fmt.Errorf("header field exceeds %d bytes", maxLen)
		}
		buf = append(buf, b)
	}
}

func readFullAt(r io.ReaderAt, buf []byte, off int64) (int, error) {
	n, err := r.ReadAt(buf, off)
	if n == len(buf) && (err == nil || errors.Is(err, io.EOF)) {
		return n, nil
	}
	if err == nil && n < len(buf) {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// GetAsset retrieves and decrypts an asset by its path.
// The path is normalized cross-platform before lookup.
func (ar *AssetReader) GetAsset(path string) (Asset, error) {
	normPath, err := normalizePath(path)
	if err != nil {
		return Asset{}, err
	}
	return ar.getAssetNormalized(normPath)
}

func (ar *AssetReader) getAssetNormalized(normPath string) (Asset, error) {
	ar.mu.RLock()
	if ar.closed {
		ar.mu.RUnlock()
		return Asset{}, ErrClosed
	}

	entry, ok := ar.entries[normPath]
	if !ok {
		ar.mu.RUnlock()
		return Asset{}, fmt.Errorf("%w: %s", ErrAssetNotFound, normPath)
	}

	if cached, ok := ar.cache[normPath]; ok {
		out := make([]byte, len(cached))
		copy(out, cached)
		ar.mu.RUnlock()
		return Asset{
			Path:    entry.path,
			Type:    entry.assetType,
			Content: out,
		}, nil
	}

	if entry.rawSize > uint64(ar.maxUncompressedSize) {
		maxSize := ar.maxUncompressedSize
		ar.mu.RUnlock()
		return Asset{}, fmt.Errorf("%w: %s size %d exceeds limit %d", ErrAssetTooLarge, normPath, entry.rawSize, maxSize)
	}

	cipherBuf := make([]byte, entry.cipherSize)
	_, err := readFullAt(ar.readerAt, cipherBuf, int64(entry.offset))
	gcm := ar.gcm
	maxSize := ar.maxUncompressedSize
	cacheEnabled := ar.cacheEnabled
	ar.mu.RUnlock()

	if err != nil {
		return Asset{}, fmt.Errorf("%w: read %s: %v", ErrInvalidArchive, normPath, err)
	}

	nonceSize := gcm.NonceSize()
	var aadBuf [256]byte
	aad := appendEntryAAD(aadBuf[:0], entry.path, entry.assetType, entry.rawSize, entry.flags)

	ciphertext := cipherBuf[nonceSize:]
	plain, err := gcm.Open(ciphertext[:0], cipherBuf[:nonceSize], ciphertext, aad)
	if err != nil {
		return Asset{}, fmt.Errorf("%w: decrypt %s: %v", ErrInvalidArchive, normPath, err)
	}

	var content []byte
	if entry.flags&flagCompressed != 0 {
		content, err = decompressGzipExact(plain, entry.rawSize, maxSize)
		if err != nil {
			return Asset{}, fmt.Errorf("decompress %s: %w", normPath, err)
		}
	} else {
		if uint64(len(plain)) != entry.rawSize {
			return Asset{}, fmt.Errorf("%w: %s size mismatch (got %d, want %d)", ErrInvalidArchive, normPath, len(plain), entry.rawSize)
		}
		content = plain
	}

	if cacheEnabled {
		ar.mu.Lock()
		if !ar.closed {
			if _, exists := ar.cache[normPath]; !exists {
				cp := make([]byte, len(content))
				copy(cp, content)
				ar.cache[normPath] = cp
			}
		}
		ar.mu.Unlock()
	}

	return Asset{
		Path:    entry.path,
		Type:    entry.assetType,
		Content: content,
	}, nil
}

// Has reports whether an asset with the given path exists in the archive.
func (ar *AssetReader) Has(path string) bool {
	normPath, err := normalizePath(path)
	if err != nil {
		return false
	}
	ar.mu.RLock()
	_, ok := ar.entries[normPath]
	ar.mu.RUnlock()
	return ok
}

// List returns a sorted copy of all normalized asset paths in the archive.
func (ar *AssetReader) List() []string {
	ar.mu.RLock()
	out := slices.Clone(ar.paths)
	ar.mu.RUnlock()
	return out
}

// Len returns the number of assets stored in the archive.
func (ar *AssetReader) Len() int {
	ar.mu.RLock()
	n := len(ar.entries)
	ar.mu.RUnlock()
	return n
}

// Close releases any underlying file handle and clears the in-memory cache.
// Calling Close multiple times is safe and idempotent.
func (ar *AssetReader) Close() error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	if ar.closed {
		return nil
	}
	ar.closed = true
	ar.cache = nil

	if ar.closer != nil {
		err := ar.closer.Close()
		ar.closer = nil
		return err
	}
	return nil
}
