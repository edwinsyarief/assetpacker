package assetpacker

import (
	"fmt"
	"os"
)

// Asset defines an asset with its type and content.
type Asset struct {
	Path    string
	Type    string
	Content []byte
}

func openFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", path, err)
	}

	return content, nil
}
