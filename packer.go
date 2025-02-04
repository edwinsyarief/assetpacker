package assetpacker

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// packAssets compresses, encrypts, and writes assets to a binary file.
func PackAssets(assets []Asset, outputPath string, key []byte) error {
	// Use AES for encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Write to file
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write each asset
	for _, asset := range assets {
		asset.Content, err = openFile(asset.Path)
		if err != nil {
			return err
		}

		compressed, err := compressAsset(asset.Content)
		if err != nil {
			return err
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}

		encrypted := gcm.Seal(nonce, nonce, compressed, nil)

		// Debug - Print what's being written
		fmt.Printf("Writing metadata for %s: %s:%s:%d:\n", asset.Path, asset.Path, asset.Type, len(encrypted))

		// Write asset metadata followed by encrypted content
		_, err = file.WriteString(fmt.Sprintf("%s:%s:%d:", asset.Path, asset.Type, len(encrypted)))
		if err != nil {
			return err
		}
		_, err = file.Write(encrypted)
		if err != nil {
			return err
		}
	}
	return nil
}

// compressAsset uses gzip to compress the asset data.
func compressAsset(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
