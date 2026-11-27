package assetpacker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// Sentinel errors returned by assetpacker operations.
var (
	// ErrAssetNotFound is returned when an asset path does not exist in the archive.
	ErrAssetNotFound = errors.New("assetpacker: asset not found")
	// ErrInvalidPath is returned when an asset path is empty, invalid, or attempts directory traversal.
	ErrInvalidPath = errors.New("assetpacker: invalid asset path")
	// ErrDuplicatePath is returned when two assets normalize to the same archive path.
	ErrDuplicatePath = errors.New("assetpacker: duplicate asset path")
	// ErrInvalidArchive is returned when an archive header, trailer, TOC, or payload is corrupted or truncated.
	ErrInvalidArchive = errors.New("assetpacker: invalid or corrupted archive")
	// ErrUnsupportedVersion is returned when an archive uses an unsupported APAK format version or flags.
	ErrUnsupportedVersion = errors.New("assetpacker: unsupported archive version")
	// ErrAssetTooLarge is returned when an asset exceeds the configured maximum uncompressed size limit.
	ErrAssetTooLarge = errors.New("assetpacker: asset exceeds maximum uncompressed size")
	// ErrClosed is returned when an operation is attempted on a closed AssetReader.
	ErrClosed = errors.New("assetpacker: asset reader is closed")
)

// Binary format v2 constants.
const (
	v2Version     uint16 = 2
	v2Flags       uint16 = 0
	v2HeaderSize         = 8  // 4-byte magic + uint16 version + uint16 flags
	v2TrailerSize        = 16 // uint64 tocOffset + uint32 tocCipherLen + 4-byte magic
	v2MinSize            = v2HeaderSize + v2TrailerSize

	flagCompressed uint8 = 1 << 0

	defaultMaxUncompressedSize int64 = 256 << 20 // 256 MiB
	maxV1HeaderFieldLen              = 4096

	entryAADPrefix = "APAK-ENTRY-v2"
)

var (
	apakMagic = [4]byte{'A', 'P', 'A', 'K'}
	tocAAD    = []byte("APAK-TOC-v2")
)

// Asset defines an asset with its virtual archive path, type, content, and optional disk source path.
type Asset struct {
	// Path is the virtual path of the asset inside the archive.
	// When packing, if Content is empty and SourcePath is empty, Path is also used as the disk source path.
	Path string
	// Type is an application-defined asset type tag (e.g. "image", "audio", "json").
	Type string
	// Content holds the raw asset bytes. When packing, if len(Content) > 0, Content is used directly
	// instead of reading from disk.
	Content []byte
	// SourcePath is an optional disk path used when packing so the virtual archive Path can differ
	// from the file location on disk.
	SourcePath string
}

// normalizePath cleans and validates an archive asset path across platforms.
// It converts backslashes to forward slashes, strips leading slashes and "./",
// cleans redundant segments, and rejects empty paths, null bytes, and ".." traversal.
func normalizePath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return "", fmt.Errorf("%w: %q contains null byte", ErrInvalidPath, raw)
	}

	p := strings.ReplaceAll(raw, "\\", "/")

	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q contains parent traversal", ErrInvalidPath, raw)
		}
	}

	p = strings.TrimLeft(p, "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "/")

	if p == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") || !fs.ValidPath(p) {
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, raw)
	}

	return p, nil
}

// appendEntryAAD appends the authenticated additional data (AAD) for a v2 entry to dst.
// Binding (normalizedPath, assetType, rawSize, flags) prevents metadata tampering or entry swapping.
func appendEntryAAD(dst []byte, normPath, assetType string, rawSize uint64, flags uint8) []byte {
	dst = append(dst, entryAADPrefix...)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(normPath)))
	dst = append(dst, normPath...)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(assetType)))
	dst = append(dst, assetType...)
	dst = binary.LittleEndian.AppendUint64(dst, rawSize)
	dst = append(dst, flags)
	return dst
}

// shouldSkipCompression reports whether the file extension represents an already-compressed format.
func shouldSkipCompression(normPath string) bool {
	switch strings.ToLower(path.Ext(normPath)) {
	case ".png", ".jpg", ".jpeg", ".webp", ".gif",
		".ogg", ".mp3", ".flac", ".aac", ".m4a",
		".mp4", ".webm",
		".woff2",
		".zip", ".gz", ".br", ".zst":
		return true
	default:
		return false
	}
}

// inferAssetType returns a canonical asset type tag derived from the file extension.
func inferAssetType(normPath string) string {
	switch strings.ToLower(path.Ext(normPath)) {
	case ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tga", ".ico", ".svg", ".qoi":
		return "image"
	case ".ogg", ".mp3", ".wav", ".flac", ".aac", ".m4a", ".opus":
		return "audio"
	case ".ttf", ".otf", ".woff", ".woff2", ".fnt":
		return "font"
	case ".kage", ".glsl", ".vert", ".frag", ".wgsl", ".hlsl", ".spv":
		return "shader"
	case ".json", ".tmj", ".tsj":
		return "json"
	case ".txt", ".xml", ".yaml", ".yml", ".toml", ".csv", ".ini", ".cfg", ".md", ".tmx", ".tsx", ".lua":
		return "text"
	default:
		return "binary"
	}
}
