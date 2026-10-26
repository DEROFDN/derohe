package hf4archive

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Summary is the deterministic, non-secret description of a validated bundle.
type Summary struct {
	Network           string `json:"network"`
	ArchiveID         string `json:"archive_id"`
	SourceID          string `json:"source_id"`
	OperatorID        string `json:"operator_id"`
	FirstTopoHeight   uint64 `json:"first_topo_height"`
	StartBlockID      string `json:"start_block_id,omitempty"`
	StartStateRoot    string `json:"start_state_root,omitempty"`
	ThroughTopoHeight uint64 `json:"through_topo_height"`
	Blocks            uint64 `json:"blocks"`
	Transactions      uint64 `json:"transactions"`
	BodyBytes         uint64 `json:"body_bytes"`
	ManifestSHA256    string `json:"manifest_sha256"`
	BlocksSHA256      string `json:"blocks_sha256"`
	BodiesSHA256      string `json:"bodies_sha256"`
	SignatureSHA256   string `json:"signature_sha256"`
	SigningKeySHA256  string `json:"signing_key_sha256"`
}

// Bundle is a fully validated archive directory.
type Bundle struct {
	Dir              string
	Manifest         Manifest
	ManifestSHA256   [32]byte
	SignatureSHA256  [32]byte
	SigningKeySHA256 [32]byte
	BlocksSHA256     [32]byte
	BodiesSHA256     [32]byte
	Summary          Summary
}

// OpenBundle reads, authenticates, and fully validates one archive bundle.
// The approved source and anchor must come from a trusted, out-of-band source.
func OpenBundle(dir string, approved ApprovedSource, expectedNetwork string, anchor Anchor) (*Bundle, error) {
	if err := validateRegularDir(dir); err != nil {
		return nil, err
	}
	if err := anchor.validate(); err != nil {
		return nil, fmt.Errorf("invalid approved anchor: %w", err)
	}

	manifestBytes, err := readRegularFile(filepath.Join(dir, ManifestName), MaxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ManifestName, err)
	}
	var manifest Manifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode %s: %w", ManifestName, err)
	}
	if err := validateManifest(manifest, approved, expectedNetwork, anchor); err != nil {
		return nil, fmt.Errorf("validate %s: %w", ManifestName, err)
	}
	signatureSHA256, signingKeySHA256, err := verifyManifestSignature(dir, manifestBytes, approved)
	if err != nil {
		return nil, err
	}

	blockFile, err := openRegularFile(filepath.Join(dir, BlocksName), 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", BlocksName, err)
	}
	defer blockFile.Close()
	bodyFile, err := openRegularFile(filepath.Join(dir, BodiesName), 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", BodiesName, err)
	}
	defer bodyFile.Close()

	// Hash and scan the same open descriptors so a path cannot be swapped
	// between authentication and parsing.
	blocksSHA256, err := hashAndRewind(blockFile)
	if err != nil {
		return nil, fmt.Errorf("hash %s: %w", BlocksName, err)
	}
	bodiesSHA256, err := hashAndRewind(bodyFile)
	if err != nil {
		return nil, fmt.Errorf("hash %s: %w", BodiesName, err)
	}
	declaredBlocks, _ := parseSHA256(manifest.BlocksSHA256)
	declaredBodies, _ := parseSHA256(manifest.BodiesSHA256)
	if blocksSHA256 != declaredBlocks {
		return nil, fmt.Errorf("%s SHA-256 does not match the manifest", BlocksName)
	}
	if bodiesSHA256 != declaredBodies {
		return nil, fmt.Errorf("%s SHA-256 does not match the manifest", BodiesName)
	}

	blockScanner := bufio.NewScanner(blockFile)
	blockScanner.Split(scanArchiveJSONL)
	blockScanner.Buffer(make([]byte, 64*1024), MaxBlockRowSize+1)
	bodyScanner := bufio.NewScanner(bodyFile)
	bodyScanner.Split(scanArchiveJSONL)
	bodyScanner.Buffer(make([]byte, 64*1024), MaxBodyRowSize+1)

	var (
		blockCount       uint64
		transactionCount uint64
		bodyBytes        uint64
		expectedTopo     = manifest.FirstTopoHeight
		lastTopo         uint64
	)
	seenBlocks := make(map[[32]byte]bool)
	for blockScanner.Scan() {
		line := append([]byte(nil), blockScanner.Bytes()...)
		if len(line) == 0 {
			return nil, fmt.Errorf("empty %s row at index %d", BlocksName, blockCount)
		}
		var block BlockRow
		if err := decodeStrictJSON(line, &block); err != nil {
			return nil, fmt.Errorf("decode %s row at index %d: %w", BlocksName, blockCount, err)
		}
		if block.TransactionHashes == nil {
			return nil, fmt.Errorf("%s row at index %d has a null transaction_hashes", BlocksName, blockCount)
		}
		if block.TopoHeight != expectedTopo {
			return nil, fmt.Errorf("%s topo_height %d out of order; want %d", BlocksName, block.TopoHeight, expectedTopo)
		}
		blockHash, err := parseHash32(block.BlockHash)
		if err != nil {
			return nil, fmt.Errorf("%s block_hash at topo %d: %w", BlocksName, block.TopoHeight, err)
		}
		if seenBlocks[blockHash] {
			return nil, fmt.Errorf("%s duplicate block hash at topo %d", BlocksName, block.TopoHeight)
		}
		seenBlocks[blockHash] = true
		if manifest.FirstTopoHeight == 0 {
			if block.TopoHeight == 0 && block.BlockHash != manifest.GenesisBlockID {
				return nil, fmt.Errorf("%s genesis block hash does not match the manifest", BlocksName)
			}
		} else if block.TopoHeight == manifest.FirstTopoHeight && block.BlockHash != manifest.StartBlockID {
			return nil, fmt.Errorf("%s section start block hash does not match the manifest", BlocksName)
		}
		if block.TopoHeight == manifest.ThroughTopoHeight && block.BlockHash != manifest.AnchorBlockID {
			return nil, fmt.Errorf("%s anchor block hash does not match the manifest", BlocksName)
		}
		seen := make(map[[32]byte]bool, len(block.TransactionHashes))
		for index, txText := range block.TransactionHashes {
			txHash, err := parseHash32(txText)
			if err != nil {
				return nil, fmt.Errorf("%s transaction_hashes[%d] at topo %d: %w", BlocksName, index, block.TopoHeight, err)
			}
			if seen[txHash] {
				return nil, fmt.Errorf("%s duplicate transaction hash at topo %d", BlocksName, block.TopoHeight)
			}
			seen[txHash] = true

			if !bodyScanner.Scan() {
				if err := bodyScanner.Err(); err != nil {
					return nil, fmt.Errorf("scan %s: %w", BodiesName, err)
				}
				return nil, fmt.Errorf("%s ended before topo %d transaction %d", BodiesName, block.TopoHeight, index)
			}
			bodyLine := append([]byte(nil), bodyScanner.Bytes()...)
			if len(bodyLine) == 0 {
				return nil, fmt.Errorf("empty %s row for topo %d transaction %d", BodiesName, block.TopoHeight, index)
			}
			var body BodyRow
			if err := decodeStrictJSON(bodyLine, &body); err != nil {
				return nil, fmt.Errorf("decode %s row for topo %d transaction %d: %w", BodiesName, block.TopoHeight, index, err)
			}
			if body.TopoHeight != block.TopoHeight || body.TransactionIndex != uint64(index) || body.TransactionHash != txText {
				return nil, fmt.Errorf("%s row for topo %d transaction %d does not match the block catalog", BodiesName, block.TopoHeight, index)
			}
			bodySHA, err := parseSHA256(body.BodySHA256)
			if err != nil {
				return nil, fmt.Errorf("%s body_sha256 for topo %d transaction %d: %w", BodiesName, block.TopoHeight, index, err)
			}
			if body.BodySize == 0 || body.BodySize > uint64((MaxBodyHexSize-2)/2) {
				return nil, fmt.Errorf("%s body_size %d for topo %d transaction %d is outside the supported range", BodiesName, body.BodySize, block.TopoHeight, index)
			}
			if err := verifyBodyFile(dir, txHash, bodySHA, body.BodySize); err != nil {
				return nil, err
			}
			transactionCount++
			bodyBytes += body.BodySize
		}
		lastTopo = block.TopoHeight
		expectedTopo++
		blockCount++
	}
	if err := blockScanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", BlocksName, err)
	}
	if blockCount == 0 {
		return nil, fmt.Errorf("%s is empty", BlocksName)
	}
	if bodyScanner.Scan() {
		return nil, fmt.Errorf("%s has more rows than %s", BodiesName, BlocksName)
	}
	if err := bodyScanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", BodiesName, err)
	}
	if lastTopo != manifest.ThroughTopoHeight {
		return nil, fmt.Errorf("last block topo %d does not match manifest through_topo_height %d", lastTopo, manifest.ThroughTopoHeight)
	}

	manifestHash := sha256.Sum256(manifestBytes)
	summary := Summary{
		Network:           manifest.Network,
		ArchiveID:         manifest.ArchiveID,
		SourceID:          manifest.SourceID,
		OperatorID:        manifest.OperatorID,
		FirstTopoHeight:   manifest.FirstTopoHeight,
		StartBlockID:      manifest.StartBlockID,
		StartStateRoot:    manifest.StartStateRoot,
		ThroughTopoHeight: manifest.ThroughTopoHeight,
		Blocks:            blockCount,
		Transactions:      transactionCount,
		BodyBytes:         bodyBytes,
		ManifestSHA256:    hex.EncodeToString(manifestHash[:]),
		BlocksSHA256:      hex.EncodeToString(blocksSHA256[:]),
		BodiesSHA256:      hex.EncodeToString(bodiesSHA256[:]),
		SignatureSHA256:   hex.EncodeToString(signatureSHA256[:]),
		SigningKeySHA256:  hex.EncodeToString(signingKeySHA256[:]),
	}
	return &Bundle{
		Dir:              dir,
		Manifest:         manifest,
		ManifestSHA256:   manifestHash,
		SignatureSHA256:  signatureSHA256,
		SigningKeySHA256: signingKeySHA256,
		BlocksSHA256:     blocksSHA256,
		BodiesSHA256:     bodiesSHA256,
		Summary:          summary,
	}, nil
}

func validateRegularDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat archive directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("archive path is not a regular directory")
	}
	return nil
}

func hashAndRewind(file *os.File) ([32]byte, error) {
	var result [32]byte
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func verifyBodyFile(root string, txHash [32]byte, bodySHA [32]byte, bodySize uint64) error {
	txRoot := filepath.Join(root, TxDirName)
	txRootInfo, err := os.Lstat(txRoot)
	if err != nil {
		return fmt.Errorf("stat tx root: %w", err)
	}
	if !txRootInfo.IsDir() || txRootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("tx root is not a regular directory")
	}
	txID := hex.EncodeToString(txHash[:])
	txDir := filepath.Join(txRoot, txID)
	txDirInfo, err := os.Lstat(txDir)
	if err != nil {
		return fmt.Errorf("stat tx directory %s: %w", txID, err)
	}
	if !txDirInfo.IsDir() || txDirInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("tx path %s is not a regular directory", txID)
	}
	name := hex.EncodeToString(bodySHA[:]) + ".hex"
	encoded, err := readRegularFile(filepath.Join(txDir, name), MaxBodyHexSize)
	if err != nil {
		return fmt.Errorf("read transaction body %s/%s: %w", txID, name, err)
	}
	if bytes.HasSuffix(encoded, []byte("\r\n")) {
		encoded = encoded[:len(encoded)-2]
	} else if bytes.HasSuffix(encoded, []byte("\n")) {
		encoded = encoded[:len(encoded)-1]
	}
	text := string(encoded)
	if text == "" || strings.ToLower(text) != text || strings.TrimSpace(text) != text {
		return fmt.Errorf("transaction body %s/%s is not normalized lowercase hex", txID, name)
	}
	body, err := hex.DecodeString(text)
	if err != nil {
		return fmt.Errorf("decode transaction body %s/%s: %w", txID, name, err)
	}
	if len(body) == 0 {
		return fmt.Errorf("transaction body %s/%s is empty", txID, name)
	}
	if uint64(len(body)) != bodySize {
		return fmt.Errorf("transaction body %s/%s size %d does not match catalog size %d", txID, name, len(body), bodySize)
	}
	actual := sha256.Sum256(body)
	if actual != bodySHA {
		return fmt.Errorf("transaction body %s/%s SHA-256 does not match the catalog", txID, name)
	}
	return nil
}

func scanArchiveJSONL(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if newline := bytes.IndexByte(data, '\n'); newline >= 0 {
		line := data[:newline]
		if bytes.IndexByte(line, '\r') >= 0 {
			return 0, nil, fmt.Errorf("JSONL records must use LF line endings")
		}
		return newline + 1, line, nil
	}
	if atEOF && len(data) != 0 {
		return 0, nil, fmt.Errorf("JSONL final record is not LF-terminated")
	}
	return 0, nil, nil
}
