package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/edwinsyarief/assetpacker"
)

const defaultExcludePatterns = "*.aseprite,.DS_Store,Thumbs.db"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "pack":
		return runPack(args[1:], stdout, stderr)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown subcommand: %s\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: assetpacker <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  pack    Pack a directory into an encrypted v2 APAK archive")
	fmt.Fprintln(w, "  list    List all assets stored in an archive")
	fmt.Fprintln(w, "  verify  Decrypt and verify integrity of every asset in an archive")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Key flags (provide exactly one):")
	fmt.Fprintln(w, "  -key-env  NAME   Read encryption key from environment variable NAME")
	fmt.Fprintln(w, "  -key-file PATH   Read encryption key from file PATH")
	fmt.Fprintln(w, "  -key      VALUE  Raw encryption key string (16, 24, or 32 bytes)")
}

type keyFlags struct {
	keyEnv  string
	keyFile string
	keyRaw  string
}

func (k *keyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&k.keyEnv, "key-env", "", "environment variable containing the AES key")
	fs.StringVar(&k.keyFile, "key-file", "", "path to file containing the AES key")
	fs.StringVar(&k.keyRaw, "key", "", "raw AES key string (16, 24, or 32 bytes)")
}

func (k *keyFlags) resolve() ([]byte, error) {
	sources := 0
	if k.keyEnv != "" {
		sources++
	}
	if k.keyFile != "" {
		sources++
	}
	if k.keyRaw != "" {
		sources++
	}

	if sources == 0 {
		return nil, errors.New("missing encryption key: specify one of -key-env, -key-file, or -key")
	}
	if sources > 1 {
		return nil, errors.New("multiple key sources specified: use only one of -key-env, -key-file, or -key")
	}

	var key []byte
	switch {
	case k.keyEnv != "":
		val, ok := os.LookupEnv(k.keyEnv)
		if !ok || val == "" {
			return nil, fmt.Errorf("environment variable %q is unset or empty", k.keyEnv)
		}
		key = []byte(val)
	case k.keyFile != "":
		raw, err := os.ReadFile(k.keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file %q: %w", k.keyFile, err)
		}
		if !isValidAESKeyLen(len(raw)) {
			trimmed := bytes.TrimRight(raw, "\r\n")
			if isValidAESKeyLen(len(trimmed)) {
				raw = trimmed
			}
		}
		key = raw
	case k.keyRaw != "":
		key = []byte(k.keyRaw)
	}

	if !isValidAESKeyLen(len(key)) {
		return nil, fmt.Errorf("invalid AES key length %d bytes (must be 16, 24, or 32 bytes)", len(key))
	}
	return key, nil
}

func isValidAESKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}

func runPack(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		srcDir  string
		outPath string
		exclude string
		prefix  string
		verbose bool
		kf      keyFlags
	)

	fs.StringVar(&srcDir, "src", "", "source directory to pack (required)")
	fs.StringVar(&outPath, "out", "", "output archive file path (required)")
	fs.StringVar(&exclude, "exclude", defaultExcludePatterns, "comma-separated glob patterns to exclude")
	fs.StringVar(&prefix, "prefix", "", "optional virtual path prefix for packed assets")
	fs.BoolVar(&verbose, "v", false, "enable verbose output")
	kf.register(fs)

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if srcDir == "" || outPath == "" {
		fmt.Fprintln(stderr, "pack requires both -src and -out flags")
		fs.Usage()
		return 2
	}

	key, err := kf.resolve()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(stderr, "error creating output directory: %v\n", err)
			return 1
		}
	}

	var opts []assetpacker.PackDirOption
	if exclude != "" {
		var patterns []string
		for p := range strings.SplitSeq(exclude, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				patterns = append(patterns, p)
			}
		}
		if len(patterns) > 0 {
			opts = append(opts, assetpacker.WithExclude(patterns...))
		}
	}
	if prefix != "" {
		opts = append(opts, assetpacker.WithPathPrefix(prefix))
	}

	if err := assetpacker.PackDir(srcDir, outPath, key, opts...); err != nil {
		fmt.Fprintf(stderr, "pack failed: %v\n", err)
		return 1
	}

	if verbose {
		reader, err := assetpacker.NewAssetReader(outPath, key)
		if err != nil {
			fmt.Fprintf(stderr, "warning: packed archive could not be inspected: %v\n", err)
			return 1
		}
		defer reader.Close()

		for _, p := range reader.List() {
			info, err := reader.Stat(p)
			if err != nil {
				fmt.Fprintf(stdout, "%s\n", p)
			} else {
				fmt.Fprintf(stdout, "%8d  %s\n", info.Size(), p)
			}
		}

		outInfo, _ := os.Stat(outPath)
		var outSize int64
		if outInfo != nil {
			outSize = outInfo.Size()
		}
		fmt.Fprintf(stdout, "Packed %d assets into %s (%d bytes)\n", reader.Len(), outPath, outSize)
	}

	return 0
}

func runList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		inPath  string
		verbose bool
		kf      keyFlags
	)

	fs.StringVar(&inPath, "in", "", "archive file path")
	fs.BoolVar(&verbose, "v", false, "include uncompressed byte sizes")
	kf.register(fs)

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if inPath == "" && fs.NArg() > 0 {
		inPath = fs.Arg(0)
	}
	if inPath == "" {
		fmt.Fprintln(stderr, "list requires -in <archive> or a positional archive path")
		fs.Usage()
		return 2
	}

	key, err := kf.resolve()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	reader, err := assetpacker.NewAssetReader(inPath, key)
	if err != nil {
		fmt.Fprintf(stderr, "open failed: %v\n", err)
		return 1
	}
	defer reader.Close()

	for _, p := range reader.List() {
		if verbose {
			info, err := reader.Stat(p)
			if err != nil {
				fmt.Fprintf(stderr, "stat %s failed: %v\n", p, err)
				return 1
			}
			fmt.Fprintf(stdout, "%8d  %s\n", info.Size(), p)
		} else {
			fmt.Fprintln(stdout, p)
		}
	}
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		inPath  string
		verbose bool
		kf      keyFlags
	)

	fs.StringVar(&inPath, "in", "", "archive file path")
	fs.BoolVar(&verbose, "v", false, "print each verified asset")
	kf.register(fs)

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if inPath == "" && fs.NArg() > 0 {
		inPath = fs.Arg(0)
	}
	if inPath == "" {
		fmt.Fprintln(stderr, "verify requires -in <archive> or a positional archive path")
		fs.Usage()
		return 2
	}

	key, err := kf.resolve()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	reader, err := assetpacker.NewAssetReader(inPath, key)
	if err != nil {
		fmt.Fprintf(stderr, "verify failed (open): %v\n", err)
		return 1
	}
	defer reader.Close()

	paths := reader.List()
	for _, p := range paths {
		asset, err := reader.GetAsset(p)
		if err != nil {
			fmt.Fprintf(stderr, "verify failed (%s): %v\n", p, err)
			return 1
		}
		if verbose {
			fmt.Fprintf(stdout, "OK  %8d  %-8s  %s\n", len(asset.Content), asset.Type, asset.Path)
		}
	}

	fmt.Fprintf(stdout, "OK: verified %d assets in %s\n", len(paths), inPath)
	return 0
}
