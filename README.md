# Asset Packer

`assetpacker` is a zero-dependency Go library and CLI for packing game assets into a single AES-GCM encrypted, lazily-readable binary archive (`APAK` v2) with automatic backward compatibility for legacy v1 archives.

## Features

- **Versioned Binary Format (`APAK` v2)**:
  - Fixed header (`"APAK"` + `uint16` version `2` + `uint16` flags)
  - Sequential AES-GCM encrypted asset payloads with cryptographically random nonces
  - Per-entry authenticated additional data (AAD) binding `(path, type, rawSize, flags)` to prevent metadata tampering or entry swapping
  - Encrypted footer Table of Contents (TOC) authenticated with AAD `"APAK-TOC-v2"`
  - Automatic fallback reader for legacy v1 archives
- **Lazy On-Demand Loading (`io.ReaderAt`)**:
  - Opening an archive decrypts only the footer TOC—assets are read and decrypted lazily on demand via `ReadAt`
  - Optional in-memory caching (`WithCache(true)`) returning defensive copies
  - Configurable decompression bomb protection (`WithMaxUncompressedSize`, default 256 MiB)
  - Thread-safe for concurrent reads
- **Smart Compression**:
  - Automatically skips gzip for already-compressed formats (`.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`, `.ogg`, `.mp3`, `.flac`, `.aac`, `.m4a`, `.mp4`, `.webm`, `.woff2`, `.zip`, `.gz`, `.br`, `.zst`) or whenever compressed output is not smaller than raw input
  - Uses `sync.Pool` for `gzip.Writer`, `gzip.Reader`, and scratch buffers
- **Atomic File Writes & Cross-Platform Paths**:
  - `PackAssets` writes to a temporary file, syncs, and atomically renames into place
  - Normalizes Windows/POSIX separators, rejects `..` traversal and duplicate paths, and supports Unicode and colons in virtual paths
- **Standard Library `io/fs.FS`**:
  - `*AssetReader` implements `fs.FS`, `fs.ReadFileFS`, `fs.StatFS`, and `fs.ReadDirFS`

## Installation

Library:

```sh
go get github.com/edwinsyarief/assetpacker
```

CLI tool:

```sh
go install github.com/edwinsyarief/assetpacker/cmd/assetpacker@latest
```

## Quick Start

### Packing a Directory (`PackDir`)

```go
package main

import (
	"log"

	"github.com/edwinsyarief/assetpacker"
)

func main() {
	// AES-256 key (must be 16, 24, or 32 bytes)
	key := []byte("0123456789abcdef0123456789abcdef")

	err := assetpacker.PackDir(
		"assets",
		"game_assets.pak",
		key,
		assetpacker.WithExclude("*.aseprite", ".DS_Store", "Thumbs.db"),
	)
	if err != nil {
		log.Fatal(err)
	}
}
```

### Packing Explicit Assets (`PackAssets` / `PackAssetsToBytes`)

```go
assets := []assetpacker.Asset{
	{Path: "sprites/player.png", Type: "image", SourcePath: "raw/player.png"},
	{Path: "maps/level1.json", Type: "json", Content: []byte(`{"level":1}`)},
}

if err := assetpacker.PackAssets(assets, "game_assets.pak", key); err != nil {
	log.Fatal(err)
}
```

### Reading Assets Lazily

```go
reader, err := assetpacker.NewAssetReader(
	"game_assets.pak",
	key,
	assetpacker.WithCache(false), // lazy reads with minimal memory footprint
	assetpacker.WithMaxUncompressedSize(64<<20),
)
if err != nil {
	log.Fatal(err)
}
defer reader.Close()

sprite, err := reader.GetAsset("sprites/player.png")
if err != nil {
	log.Fatal(err)
}
_ = sprite.Content
```

## `io/fs.FS` Dev-Mode Hot-Reload Pattern

Because `*assetpacker.AssetReader` implements `io/fs.FS`, your game loader can accept an `fs.FS` and seamlessly switch between loose files on disk during development and an encrypted `.pak` archive in production:

```go
func openAssetFS(devMode bool, pakPath string, key []byte) (fs.FS, func() error, error) {
	if devMode {
		// Edit sprites/maps on disk and reload immediately without repacking.
		return os.DirFS("assets"), func() error { return nil }, nil
	}

	reader, err := assetpacker.NewAssetReader(pakPath, key)
	if err != nil {
		return nil, nil, err
	}
	return reader, reader.Close, nil
}
```

## Official CLI (`cmd/assetpacker`)

Three subcommands are provided: `pack`, `list`, and `verify`.

Provide the AES key using exactly one of:
- `-key-env NAME`: read key from environment variable `NAME` (recommended)
- `-key-file PATH`: read key from a file
- `-key VALUE`: raw key string (16, 24, or 32 bytes)

```sh
# Pack an assets folder into game_assets.pak
assetpacker pack -src ./assets -out ./build/game_assets.pak -key-env GAME_ASSET_KEY -v

# List entries in the archive
assetpacker list -in ./build/game_assets.pak -key-env GAME_ASSET_KEY -v

# Decrypt and verify GCM integrity of every asset
assetpacker verify -in ./build/game_assets.pak -key-env GAME_ASSET_KEY -v
```

### VS Code Task Example (`.vscode/tasks.json`)

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Pack Game Assets",
      "type": "shell",
      "command": "assetpacker",
      "args": [
        "pack",
        "-src", "${workspaceFolder}/assets",
        "-out", "${workspaceFolder}/build/game_assets.pak",
        "-exclude", "*.aseprite,.DS_Store,Thumbs.db",
        "-key-env", "GAME_ASSET_KEY",
        "-v"
      ],
      "group": "build",
      "problemMatcher": []
    }
  ]
}
```

## WASM Usage

In Go WebAssembly (`GOOS=js GOARCH=wasm`), fetch the archive as an `ArrayBuffer`, copy raw bytes directly with `js.CopyBytesToGo` (never modify or "clean" binary ciphertext), and release all `js.Func` callbacks to prevent memory leaks:

```go
//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"github.com/edwinsyarief/assetpacker"
)

func loadAssetPackFromWasm(url string, key []byte) (*assetpacker.AssetReader, error) {
	type fetchResult struct {
		data []byte
		err  error
	}
	ch := make(chan fetchResult, 1)

	var onFetch, onFetchErr, onBuf, onBufErr js.Func
	releaseAll := func() {
		onFetch.Release()
		onFetchErr.Release()
		onBuf.Release()
		onBufErr.Release()
	}

	onBuf = js.FuncOf(func(this js.Value, args []js.Value) any {
		u8 := js.Global().Get("Uint8Array").New(args[0])
		data := make([]byte, u8.Get("length").Int())
		js.CopyBytesToGo(data, u8)
		ch <- fetchResult{data: data}
		return nil
	})
	onBufErr = js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- fetchResult{err: fmt.Errorf("arrayBuffer failed: %v", args[0])}
		return nil
	})
	onFetch = js.FuncOf(func(this js.Value, args []js.Value) any {
		resp := args[0]
		if !resp.Get("ok").Bool() {
			ch <- fetchResult{err: fmt.Errorf("HTTP %d", resp.Get("status").Int())}
			return nil
		}
		resp.Call("arrayBuffer").Call("then", onBuf).Call("catch", onBufErr)
		return nil
	})
	onFetchErr = js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- fetchResult{err: fmt.Errorf("fetch failed: %v", args[0])}
		return nil
	})

	js.Global().Call("fetch", url).Call("then", onFetch).Call("catch", onFetchErr)

	res := <-ch
	releaseAll()
	if res.err != nil {
		return nil, res.err
	}

	return assetpacker.NewAssetReaderFromBytes(res.data, key)
}
```

## Binary Format (`APAK` v2)

All multi-byte integers are little-endian:

```text
+-------------------------------------------------------------------+
| Header (8 bytes)                                                  |
|   Magic:   "APAK" (4 bytes)                                       |
|   Version: uint16 = 2                                             |
|   Flags:   uint16 = 0                                             |
+-------------------------------------------------------------------+
| Encrypted Entry Payloads (sequential)                             |
|   Entry i: nonce (12 B) || AES-GCM(payload, AAD = entry metadata) |
+-------------------------------------------------------------------+
| Encrypted Footer TOC                                              |
|   nonce (12 B) || AES-GCM(TOC bytes, AAD = "APAK-TOC-v2")         |
+-------------------------------------------------------------------+
| Trailer (16 bytes)                                                |
|   tocOffset:    uint64                                            |
|   tocCipherLen: uint32                                            |
|   Magic:        "APAK" (4 bytes)                                  |
+-------------------------------------------------------------------+
```
