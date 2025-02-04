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
