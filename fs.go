package assetpacker

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"slices"
	"time"
)

var (
	_ fs.FS         = (*AssetReader)(nil)
	_ fs.ReadFileFS = (*AssetReader)(nil)
	_ fs.StatFS     = (*AssetReader)(nil)
	_ fs.ReadDirFS  = (*AssetReader)(nil)
)

func (ar *AssetReader) buildDirIndex() {
	dirSet := map[string]struct{}{".": {}}
	dirChildren := map[string]map[string]struct{}{
		".": {},
	}

	for _, p := range ar.paths {
		child := p
		for {
			dir := path.Dir(child)
			base := path.Base(child)
			dirSet[dir] = struct{}{}
			if dirChildren[dir] == nil {
				dirChildren[dir] = make(map[string]struct{})
			}
			dirChildren[dir][base] = struct{}{}
			if dir == "." {
				break
			}
			child = dir
		}
	}

	dirs := make(map[string][]string, len(dirChildren))
	for dir, children := range dirChildren {
		names := make([]string, 0, len(children))
		for name := range children {
			names = append(names, name)
		}
		slices.Sort(names)
		dirs[dir] = names
	}

	ar.dirSet = dirSet
	ar.dirs = dirs
}

func (ar *AssetReader) dirEntriesLocked(dir string) []fs.DirEntry {
	names := ar.dirs[dir]
	out := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		fullPath := name
		if dir != "." {
			fullPath = dir + "/" + name
		}
		if entry, isFile := ar.entries[fullPath]; isFile {
			out = append(out, fs.FileInfoToDirEntry(assetFileInfo{
				name:  name,
				size:  int64(entry.rawSize),
				isDir: false,
			}))
		} else {
			out = append(out, fs.FileInfoToDirEntry(assetFileInfo{
				name:  name,
				size:  0,
				isDir: true,
			}))
		}
	}
	return out
}

// Open opens the named asset or virtual directory for reading, implementing io/fs.FS.
func (ar *AssetReader) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	ar.mu.RLock()
	if ar.closed {
		ar.mu.RUnlock()
		return nil, &fs.PathError{Op: "open", Path: name, Err: ErrClosed}
	}
	_, isFile := ar.entries[name]
	if !isFile {
		if _, isDir := ar.dirSet[name]; isDir {
			entries := ar.dirEntriesLocked(name)
			ar.mu.RUnlock()
			return &assetDir{
				fullPath: name,
				info: assetFileInfo{
					name:  path.Base(name),
					isDir: true,
				},
				entries: entries,
			}, nil
		}
		ar.mu.RUnlock()
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	ar.mu.RUnlock()

	asset, err := ar.getAssetNormalized(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return &assetFile{
		fullPath: name,
		info: assetFileInfo{
			name:  path.Base(name),
			size:  int64(len(asset.Content)),
			isDir: false,
		},
		reader: bytes.NewReader(asset.Content),
	}, nil
}

// ReadFile reads and returns the full decrypted bytes of the named asset, implementing io/fs.ReadFileFS.
func (ar *AssetReader) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrInvalid}
	}

	ar.mu.RLock()
	if ar.closed {
		ar.mu.RUnlock()
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: ErrClosed}
	}
	_, isFile := ar.entries[name]
	if !isFile {
		_, isDir := ar.dirSet[name]
		ar.mu.RUnlock()
		if isDir {
			return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrInvalid}
		}
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrNotExist}
	}
	ar.mu.RUnlock()

	asset, err := ar.getAssetNormalized(name)
	if err != nil {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: err}
	}
	return asset.Content, nil
}

// Stat returns file metadata for the named asset or virtual directory without decrypting payload bytes,
// implementing io/fs.StatFS.
func (ar *AssetReader) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}

	ar.mu.RLock()
	defer ar.mu.RUnlock()

	if ar.closed {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: ErrClosed}
	}
	if entry, isFile := ar.entries[name]; isFile {
		return assetFileInfo{
			name:  path.Base(name),
			size:  int64(entry.rawSize),
			isDir: false,
		}, nil
	}
	if _, isDir := ar.dirSet[name]; isDir {
		return assetFileInfo{
			name:  path.Base(name),
			size:  0,
			isDir: true,
		}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

// ReadDir returns the sorted directory entries of the named virtual directory, implementing io/fs.ReadDirFS.
func (ar *AssetReader) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}

	ar.mu.RLock()
	defer ar.mu.RUnlock()

	if ar.closed {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: ErrClosed}
	}
	if _, isDir := ar.dirSet[name]; isDir {
		return ar.dirEntriesLocked(name), nil
	}
	if _, isFile := ar.entries[name]; isFile {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
}

type assetFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (fi assetFileInfo) Name() string { return fi.name }
func (fi assetFileInfo) Size() int64  { return fi.size }
func (fi assetFileInfo) Mode() fs.FileMode {
	if fi.isDir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (fi assetFileInfo) ModTime() time.Time { return time.Time{} }
func (fi assetFileInfo) IsDir() bool        { return fi.isDir }
func (fi assetFileInfo) Sys() any           { return nil }

type assetFile struct {
	fullPath string
	info     assetFileInfo
	reader   *bytes.Reader
	closed   bool
}

func (f *assetFile) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func (f *assetFile) Read(p []byte) (int, error) {
	if f.closed {
		return 0, &fs.PathError{Op: "read", Path: f.fullPath, Err: fs.ErrClosed}
	}
	return f.reader.Read(p)
}

func (f *assetFile) ReadAt(p []byte, off int64) (int, error) {
	if f.closed {
		return 0, &fs.PathError{Op: "readat", Path: f.fullPath, Err: fs.ErrClosed}
	}
	return f.reader.ReadAt(p, off)
}

func (f *assetFile) Seek(offset int64, whence int) (int64, error) {
	if f.closed {
		return 0, &fs.PathError{Op: "seek", Path: f.fullPath, Err: fs.ErrClosed}
	}
	return f.reader.Seek(offset, whence)
}

func (f *assetFile) Close() error {
	f.closed = true
	return nil
}

type assetDir struct {
	fullPath string
	info     assetFileInfo
	entries  []fs.DirEntry
	offset   int
	closed   bool
}

func (d *assetDir) Stat() (fs.FileInfo, error) {
	return d.info, nil
}

func (d *assetDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.fullPath, Err: fs.ErrInvalid}
}

func (d *assetDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.closed {
		return nil, &fs.PathError{Op: "readdir", Path: d.fullPath, Err: fs.ErrClosed}
	}
	remaining := len(d.entries) - d.offset
	if n <= 0 {
		out := d.entries[d.offset:]
		d.offset = len(d.entries)
		return out, nil
	}
	if remaining == 0 {
		return nil, io.EOF
	}
	if n > remaining {
		n = remaining
	}
	out := d.entries[d.offset : d.offset+n]
	d.offset += n
	return out, nil
}

func (d *assetDir) Close() error {
	d.closed = true
	return nil
}
