# Asset Packer

## Overview

Asset Packer is a powerful tool designed to streamline the packaging and management of game assets. It provides a seamless workflow for developers, ensuring that assets are efficiently packed and ready for use in the game.

## Installation

```sh
go get github.com/edwinsyarief/assetpacker
```

### Secure Asset Pipeline

- **Encrypted Assets**: All game assets (images, audio, maps) are encrypted using AES-GCM encryption
- **Compression**: Assets are automatically compressed using gzip before encryption
- **Streamlined Loading**: Fast asset loading with built-in decompression and decryption

### Asset Types Support

- Sprites and animations
- Audio files (BGM, SFX)
- Map data and configurations
- UI elements and fonts

### Security Features

- AES-GCM authenticated encryption
- Secure random nonce generation
- Key rotation support
- Protected asset integrity

This system ensures your game assets are protected while maintaining excellent performance and developer experience.

## Quick Start Example

Here's a simple example of packing game assets:

```go
package main

import (
    "fmt"
    "github.com/edwinsyarief/assetpacker"
)

func main() {
    // Define your game assets
    assets := []assetpacker.Asset{
        {Path: "assets/sprites/player.png", Type: "sprite"},
        {Path: "assets/audio/background.mp3", Type: "audio"},
        {Path: "assets/maps/level1.json", Type: "map"},
    }

    // Your secret key (32 bytes)
    key := []byte("your-secret-key-32-bytes-required!")

    // Pack assets into a single encrypted file
    err := assetpacker.PackAssets(assets, "game_assets.pak", key)
    if err != nil {
        fmt.Printf("Failed to pack assets: %v\n", err)
        return
    }

    // Later, in your game code:
    reader, err := assetpacker.NewAssetReader("game_assets.pak", key)
    if err != nil {
        fmt.Printf("Failed to read assets: %v\n", err)
        return
    }

    fmt.Println("Assets packed and ready for your game!")
}
```

## WASM Example

We can also use WASM to load the game assets.

```go
// Load the game_assets.pak from the web environment
 assetBin, err := loadAssetPackFromWasm("./game_assets.pak")
 if err != nil {
  panic(err)
 }

 // Initialize the asset reader with the binary data instead of a file path
 reader, err := asset_packer.NewAssetReaderFromBytes(assetBin, key)
 if err != nil {
  panic(err)
 }


func loadAssetPackFromWasm(path string) ([]byte, error) {
 fmt.Printf("Attempting to load asset from WASM: %s\n", path)

 done := make(chan struct{})
 var result []byte
 var err error

 js.Global().Call("fetch", path).Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
  response := args[0]
  // Check if the response is OK
  if !response.Get("ok").Bool() {
   err = fmt.Errorf("HTTP error, status %d", response.Get("status").Int())
   close(done)
   return nil
  }

  // Convert response to ArrayBuffer
  response.Call("arrayBuffer").Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
   jsArrayBuffer := args[0]
   jsUint8Array := js.Global().Get("Uint8Array").New(jsArrayBuffer)

   // Convert to Go slice
   result = make([]byte, jsUint8Array.Get("length").Int())
   js.CopyBytesToGo(result, jsUint8Array)
   close(done)
   return nil
  })).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
   err = fmt.Errorf("failed to convert response to array buffer: %v", args[0].String())
   close(done)
   return nil
  }))
  return nil
 })).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
  err = fmt.Errorf("fetch error: %v", args[0].String())
  close(done)
  return nil
 }))

 <-done

 if err != nil {
  return nil, err
 }

 fmt.Printf("Fetched data length: %d, first 10 bytes: %v, last 10 bytes: %v\n", len(result), result[:10], result[len(result)-10:])

 // Clean binary data if necessary
 cleanedData := cleanBinaryData(result)

 return cleanedData, nil
}

// Clean up the binary data by removing Unicode Replacement Characters
func cleanBinaryData(data []byte) []byte {
 var clean []byte
 for i := 0; i < len(data); {
  if i+2 < len(data) && data[i] == 239 && data[i+1] == 191 && data[i+2] == 189 {
   // Skip the three bytes representing the replacement character
   i += 3
  } else {
   clean = append(clean, data[i])
   i++
  }
 }
 return clean
}
```

The HTML script:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Your Game</title>
  </head>
  <body>
    <script src="wasm_exec.js"></script>
    <script>
      console.log(
        "Go object:",
        typeof Go !== "undefined" ? "Go exists" : "Go is not defined"
      );
      const go = new Go();
      WebAssembly.instantiateStreaming(fetch("yourgame.wasm"), go.importObject)
        .then((result) => {
          go.run(result.instance);
        })
        .catch((err) => {
          console.error("Failed to load WASM module:", err);
        });
    </script>
  </body>
</html>
```
