package assetpacker

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"sync"
)

const maxPooledBufCap = 1 << 20 // 1 MiB

var (
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}

	gzipWriterPool = sync.Pool{
		New: func() any {
			return gzip.NewWriter(io.Discard)
		},
	}

	gzipReaderPool sync.Pool

	// emptyGzip is a minimal valid gzip stream used to detach large source buffers
	// from pooled *gzip.Reader instances before returning them to gzipReaderPool.
	emptyGzip = func() []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_ = w.Close()
		return b.Bytes()
	}()
)

func getBuffer() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func putBuffer(buf *bytes.Buffer) {
	if buf.Cap() > maxPooledBufCap {
		return
	}
	buf.Reset()
	bufferPool.Put(buf)
}

// compressGzipInto compresses data into dst using a pooled gzip.Writer.
func compressGzipInto(dst *bytes.Buffer, data []byte) error {
	dst.Reset()

	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(dst)
	defer func() {
		gz.Reset(io.Discard)
		gzipWriterPool.Put(gz)
	}()

	if _, err := gz.Write(data); err != nil {
		return err
	}
	return gz.Close()
}

func acquireGzipReader(r io.Reader) (*gzip.Reader, error) {
	if v := gzipReaderPool.Get(); v != nil {
		gz := v.(*gzip.Reader)
		if err := gz.Reset(r); err != nil {
			_ = gz.Reset(bytes.NewReader(emptyGzip))
			gzipReaderPool.Put(gz)
			return nil, err
		}
		return gz, nil
	}
	return gzip.NewReader(r)
}

func releaseGzipReader(gz *gzip.Reader) {
	_ = gz.Close()
	if err := gz.Reset(bytes.NewReader(emptyGzip)); err == nil {
		gzipReaderPool.Put(gz)
	}
}

// decompressGzipBounded decompresses a gzip stream up to maxSize bytes using pooled resources.
// Used for legacy v1 entries where the exact uncompressed size is not stored in a TOC.
func decompressGzipBounded(data []byte, maxSize int64) ([]byte, error) {
	gz, err := acquireGzipReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer releaseGzipReader(gz)

	buf := getBuffer()
	defer putBuffer(buf)

	if _, err := io.Copy(buf, io.LimitReader(gz, maxSize+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > maxSize {
		return nil, fmt.Errorf("%w: decompressed size exceeds limit %d", ErrAssetTooLarge, maxSize)
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// decompressGzipExact decompresses a v2 gzip stream into an exact-sized slice of expectedSize bytes,
// verifying that it neither exceeds maxSize nor produces fewer/more bytes than expectedSize.
func decompressGzipExact(data []byte, expectedSize uint64, maxSize int64) ([]byte, error) {
	if expectedSize > uint64(maxSize) {
		return nil, fmt.Errorf("%w: size %d exceeds limit %d", ErrAssetTooLarge, expectedSize, maxSize)
	}

	gz, err := acquireGzipReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer releaseGzipReader(gz)

	out := make([]byte, expectedSize)
	if expectedSize > 0 {
		if _, err := io.ReadFull(gz, out); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
	}

	var extra [1]byte
	n, err := io.ReadFull(gz, extra[:])
	if n > 0 {
		return nil, fmt.Errorf("%w: decompressed stream exceeds declared size %d", ErrAssetTooLarge, expectedSize)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return out, nil
}
