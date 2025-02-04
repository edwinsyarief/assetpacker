package assetpacker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"strconv"
)

// AssetReader manages the decrypted assets.
type AssetReader struct {
	assets map[string]Asset
}

// NewAssetReader initializes and returns an AssetReader with decrypted assets from a file.
func NewAssetReader(filePath string, key []byte) (*AssetReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	assets := make(map[string]Asset)
	for {
		// Read until next colon for path
		path, err := readUntilColon(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading path: %v", err)
		}

		// Read type
		typeStr, err := readUntilColon(reader)
		if err != nil {
			return nil, fmt.Errorf("error reading type: %v", err)
		}

		// Read size
		sizeStr, err := readUntilColon(reader)
		if err != nil {
			return nil, fmt.Errorf("error reading size: %v", err)
		}

		sizeInt, err := strconv.Atoi(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("error converting size to int: %v", err)
		}

		// Read encrypted content
		encrypted := make([]byte, sizeInt)
		bytesRead, err := io.ReadFull(reader, encrypted)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				fmt.Printf("Warning: Read only %d bytes out of %d for asset %s\n", bytesRead, sizeInt, path)
				encrypted = encrypted[:bytesRead] // Adjust to what was actually read
			} else {
				return nil, fmt.Errorf("error reading asset content for %s: %v", path, err)
			}
		}

		// Decrypt
		nonceSize := gcm.NonceSize()
		if len(encrypted) < nonceSize {
			return nil, fmt.Errorf("not enough data for nonce for asset %s", path)
		}
		nonce, content := encrypted[:nonceSize], encrypted[nonceSize:]
		decrypted, err := gcm.Open(nil, nonce, content, nil)
		if err != nil {
			return nil, fmt.Errorf("error decrypting content for %s: %v", path, err)
		}

		// Decompress
		gz, err := gzip.NewReader(bytes.NewReader(decrypted))
		if err != nil {
			return nil, fmt.Errorf("error creating gzip reader for %s: %v", path, err)
		}
		content, err = io.ReadAll(gz)
		if err != nil {
			return nil, fmt.Errorf("error decompressing content for %s: %v", path, err)
		}
		gz.Close()

		assets[path] = Asset{Path: path, Type: typeStr, Content: content}
	}

	return &AssetReader{assets: assets}, nil
}

// NewAssetReaderFromBytes initializes and returns an AssetReader with decrypted assets from byte slice data.
func NewAssetReaderFromBytes(data []byte, key []byte) (*AssetReader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(bytes.NewReader(data)) // Corrected to use bufio.NewReader for consistency with readUntilColon
	assets := make(map[string]Asset)
	for {
		// Read until next colon for path
		path, err := readUntilColon(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading path: %v", err)
		}

		// Read type
		typeStr, err := readUntilColon(reader)
		if err != nil {
			return nil, fmt.Errorf("error reading type: %v", err)
		}

		// Read size
		sizeStr, err := readUntilColon(reader)
		if err != nil {
			return nil, fmt.Errorf("error reading size: %v", err)
		}

		sizeInt, err := strconv.Atoi(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("error converting size to int: %v", err)
		}

		// Read encrypted content
		encrypted := make([]byte, sizeInt)
		bytesRead, err := io.ReadFull(reader, encrypted)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				fmt.Printf("Warning: Read only %d bytes out of %d for asset %s\n", bytesRead, sizeInt, path)
				encrypted = encrypted[:bytesRead] // Adjust to what was actually read
			} else {
				return nil, fmt.Errorf("error reading asset content for %s: %v", path, err)
			}
		}

		// Decrypt
		nonceSize := gcm.NonceSize()
		if len(encrypted) < nonceSize {
			return nil, fmt.Errorf("not enough data for nonce for asset %s", path)
		}
		nonce, content := encrypted[:nonceSize], encrypted[nonceSize:]
		decrypted, err := gcm.Open(nil, nonce, content, nil)
		if err != nil {
			return nil, fmt.Errorf("error decrypting content for %s: %v", path, err)
		}

		// Decompress
		gz, err := gzip.NewReader(bytes.NewReader(decrypted))
		if err != nil {
			return nil, fmt.Errorf("error creating gzip reader for %s: %v", path, err)
		}
		content, err = io.ReadAll(gz)
		if err != nil {
			return nil, fmt.Errorf("error decompressing content for %s: %v", path, err)
		}
		gz.Close()

		assets[path] = Asset{Path: path, Type: typeStr, Content: content}
	}

	return &AssetReader{assets: assets}, nil
}

// readUntilColon reads from the reader until it hits a colon or an error occurs.
func readUntilColon(r *bufio.Reader) (string, error) {
	var buffer bytes.Buffer
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == ':' {
			return buffer.String(), nil
		}
		buffer.WriteByte(b)
	}
}

// GetAsset retrieves an asset by its path including its type information.
func (ar *AssetReader) GetAsset(path string) (Asset, error) {
	if asset, ok := ar.assets[path]; ok {
		return asset, nil
	}
	return Asset{}, fmt.Errorf("asset not found: %s", path)
}
