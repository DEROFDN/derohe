// Package hf4archive validates signed HF4 supply-archive bundles before they
// are accepted for review. It verifies integrity and pairwise agreement, not
// the truth or independence of the underlying collection.
package hf4archive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// SchemaVersion is the only archive manifest schema accepted by this tool.
	SchemaVersion uint64 = 1

	ManifestName  = "manifest.json"
	SignatureName = "manifest.sig"
	BlocksName    = "blocks.jsonl"
	BodiesName    = "bodies.jsonl"
	TxDirName     = "tx"

	MaxManifestSize  int64 = 1 << 20
	MaxSignatureSize int64 = 130
	MaxBlockRowSize        = 64 << 20
	MaxBodyRowSize         = 1 << 20
	MaxBodyHexSize         = (64 << 20) + 2
)

var (
	archiveIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	numericHost       = regexp.MustCompile(`^[0-9.]+$`)
)

// Manifest is the canonical, signed description of one archive bundle. Field
// order is part of the schema: canonical JSON is Go's compact marshal output
// in this declaration order.
type Manifest struct {
	SchemaVersion     uint64 `json:"schema_version"`
	Network           string `json:"network"`
	ArchiveID         string `json:"archive_id"`
	SourceID          string `json:"source_id"`
	OperatorID        string `json:"operator_id"`
	CollectionCommand string `json:"collection_command"`
	Endpoint          string `json:"endpoint"`
	SourceCommit      string `json:"source_commit"`
	FirstTopoHeight   uint64 `json:"first_topo_height"`
	ThroughTopoHeight uint64 `json:"through_topo_height"`
	GenesisBlockID    string `json:"genesis_block_id,omitempty"`
	StartBlockID      string `json:"start_block_id,omitempty"`
	StartStateRoot    string `json:"start_state_root,omitempty"`
	AnchorBlockID     string `json:"anchor_block_id"`
	AnchorStateRoot   string `json:"anchor_state_root"`
	BlocksSHA256      string `json:"blocks_sha256"`
	BodiesSHA256      string `json:"bodies_sha256"`
}

// BlockRow is one canonical row in blocks.jsonl.
type BlockRow struct {
	TopoHeight        uint64   `json:"topo_height"`
	BlockHash         string   `json:"block_hash"`
	TransactionHashes []string `json:"transaction_hashes"`
}

// BodyRow is one canonical row in bodies.jsonl.
type BodyRow struct {
	TopoHeight       uint64 `json:"topo_height"`
	TransactionIndex uint64 `json:"transaction_index"`
	TransactionHash  string `json:"transaction_hash"`
	BodySHA256       string `json:"body_sha256"`
	BodySize         uint64 `json:"body_size"`
}

// ApprovedSource is an out-of-band trust pin. It must not be read from a
// bundle; enrollment is a separate, authenticated decision.
type ApprovedSource struct {
	SourceID         string
	OperatorID       string
	SigningPublicKey string
}

// Anchor is the independently approved chain identity the archive must cover.
type Anchor struct {
	FirstTopoHeight   uint64
	GenesisBlockID    string
	StartBlockID      string
	StartStateRoot    string
	AnchorBlockID     string
	AnchorStateRoot   string
	ThroughTopoHeight uint64
}

func (a Anchor) validate() error {
	if a.FirstTopoHeight > a.ThroughTopoHeight {
		return fmt.Errorf("first topo height %d exceeds anchor topo height %d", a.FirstTopoHeight, a.ThroughTopoHeight)
	}
	fields := []struct {
		name  string
		value string
	}{
		{"anchor block ID", a.AnchorBlockID},
		{"anchor state root", a.AnchorStateRoot},
	}
	if a.FirstTopoHeight == 0 {
		if a.StartBlockID != "" || a.StartStateRoot != "" {
			return fmt.Errorf("genesis anchor must not carry section start fields")
		}
		fields = append(fields, struct {
			name  string
			value string
		}{"genesis block ID", a.GenesisBlockID})
	} else {
		if a.GenesisBlockID != "" {
			return fmt.Errorf("section anchor must not carry a genesis block ID")
		}
		fields = append(fields,
			struct {
				name  string
				value string
			}{"start block ID", a.StartBlockID},
			struct {
				name  string
				value string
			}{"start state root", a.StartStateRoot},
		)
	}
	for _, field := range fields {
		if _, err := parseHash32(field.value); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
	}
	return nil
}

func readRegularFile(path string, maxSize int64) ([]byte, error) {
	file, err := openRegularFile(path, maxSize)
	if err != nil {
		return nil, err
	}
	var reader io.Reader = file
	if maxSize > 0 {
		reader = io.LimitReader(file, maxSize+1)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s: %w", filepath.Base(path), closeErr)
	}
	if maxSize > 0 && int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%s exceeds the %d-byte size limit", filepath.Base(path), maxSize)
	}
	return data, nil
}

func openRegularFile(path string, maxSize int64) (*os.File, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !linkInfo.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular non-symlink file", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(linkInfo, fileInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed while opening", filepath.Base(path))
	}
	if maxSize > 0 && fileInfo.Size() > maxSize {
		_ = file.Close()
		return nil, fmt.Errorf("%s exceeds the %d-byte size limit", filepath.Base(path), maxSize)
	}
	return file, nil
}

func decodeStrictJSON(data []byte, destination interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return fmt.Errorf("re-encode canonical JSON: %w", err)
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("JSON is not in canonical encoding")
	}
	return nil
}

func parseHash32(text string) ([32]byte, error) {
	var value [32]byte
	if len(text) != 64 || strings.ToLower(text) != text {
		return value, fmt.Errorf("value is not canonical lowercase 32-byte hex")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return value, err
	}
	copy(value[:], decoded)
	return value, nil
}

func parseSHA256(text string) ([32]byte, error) {
	return parseHash32(text)
}

func parsePublicKey(text string) (ed25519.PublicKey, error) {
	if len(text) != hex.EncodedLen(ed25519.PublicKeySize) || strings.ToLower(text) != text {
		return nil, fmt.Errorf("public key is not canonical lowercase Ed25519 key hex")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has length %d, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func validateSourceCommit(text string) error {
	if (len(text) != 40 && len(text) != 64) || strings.ToLower(text) != text {
		return fmt.Errorf("source_commit must be a full lowercase 40- or 64-character hex hash")
	}
	if _, err := hex.DecodeString(text); err != nil {
		return fmt.Errorf("source_commit is not valid hex: %w", err)
	}
	return nil
}

func validateCollectionCommand(text string) error {
	lower := strings.ToLower(text)
	for _, blocked := range []string{"-----begin", "private key", "password=", "passwd=", "secret=", "token=", "apikey=", "api_key=", "authorization:", "bearer "} {
		if strings.Contains(lower, blocked) {
			return fmt.Errorf("collection_command appears to contain credentials or key material")
		}
	}
	return nil
}

func validateEndpointLabel(text string) error {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return fmt.Errorf("endpoint is empty")
	}
	if strings.HasPrefix(trimmed, "//") {
		return fmt.Errorf("endpoint must be an absolute URL or a label")
	}
	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return fmt.Errorf("endpoint is not a valid URL: %w", err)
		}
		switch strings.ToLower(parsed.Scheme) {
		case "https", "http":
			if parsed.User != nil {
				return fmt.Errorf("endpoint URL must not contain userinfo or credentials")
			}
			query := strings.ToLower(parsed.RawQuery)
			for _, blocked := range []string{"token=", "secret=", "password=", "passwd=", "apikey=", "api_key=", "auth="} {
				if strings.Contains(query, blocked) {
					return fmt.Errorf("endpoint URL must not contain credentials in the query")
				}
			}
			host := parsed.Hostname()
			if host == "" {
				return fmt.Errorf("endpoint URL has no host")
			}
			if isPrivateHost(host) {
				return fmt.Errorf("endpoint looks private or internal; use a public or non-identifying label")
			}
		case "ipfs", "ipns":
			if host := parsed.Hostname(); host != "" && isPrivateHost(host) {
				return fmt.Errorf("endpoint looks private or internal; use a public or non-identifying label")
			}
		default:
			return fmt.Errorf("endpoint scheme %q is not accepted", parsed.Scheme)
		}
		return nil
	}
	host := trimmed
	if splitHost, _, err := net.SplitHostPort(trimmed); err == nil {
		host = splitHost
	}
	if isPrivateHost(host) {
		return fmt.Errorf("endpoint looks private or internal; use a public or non-identifying label")
	}
	return nil
}

func isPrivateHost(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	lower = strings.Trim(lower, "[]")
	lower = strings.TrimRight(lower, ".")
	if lower == "" {
		return true
	}
	if numericHost.MatchString(lower) {
		return true
	}
	if _, err := strconv.ParseUint(lower, 0, 64); err == nil {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".lan", ".home", ".corp"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	if lower == "localhost" {
		return true
	}
	if ip := net.ParseIP(lower); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}
	return false
}

func validateManifest(manifest Manifest, approved ApprovedSource, expectedNetwork string, anchor Anchor) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", manifest.SchemaVersion)
	}
	if manifest.Network != expectedNetwork {
		return fmt.Errorf("network mismatch: got %q, want %q", manifest.Network, expectedNetwork)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"archive_id", manifest.ArchiveID},
		{"source_id", manifest.SourceID},
		{"operator_id", manifest.OperatorID},
	} {
		if !archiveIdentifier.MatchString(field.value) {
			return fmt.Errorf("manifest %s must match %s", field.name, archiveIdentifier.String())
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"collection_command", manifest.CollectionCommand},
		{"endpoint", manifest.Endpoint},
	} {
		if strings.TrimSpace(field.value) == "" || strings.TrimSpace(field.value) != field.value {
			return fmt.Errorf("manifest %s is empty or has surrounding whitespace", field.name)
		}
	}
	if manifest.SourceID != approved.SourceID || manifest.OperatorID != approved.OperatorID {
		return fmt.Errorf("manifest source/operator identity does not match explicit approval")
	}
	if err := validateSourceCommit(manifest.SourceCommit); err != nil {
		return err
	}
	if err := validateEndpointLabel(manifest.Endpoint); err != nil {
		return err
	}
	if err := validateCollectionCommand(manifest.CollectionCommand); err != nil {
		return err
	}
	if manifest.FirstTopoHeight != anchor.FirstTopoHeight || manifest.ThroughTopoHeight != anchor.ThroughTopoHeight {
		return fmt.Errorf("archive range does not match the approved checkpoint")
	}
	if manifest.FirstTopoHeight == 0 {
		if manifest.StartBlockID != "" || manifest.StartStateRoot != "" {
			return fmt.Errorf("genesis archive must not carry section start fields")
		}
		genesisID, err := parseHash32(manifest.GenesisBlockID)
		if err != nil {
			return fmt.Errorf("manifest genesis block ID: %w", err)
		}
		expectedGenesis, _ := parseHash32(anchor.GenesisBlockID)
		if genesisID != expectedGenesis {
			return fmt.Errorf("manifest genesis block ID does not match approved anchor")
		}
	} else {
		if manifest.GenesisBlockID != "" {
			return fmt.Errorf("section archive must not carry a genesis block ID")
		}
		startID, err := parseHash32(manifest.StartBlockID)
		if err != nil {
			return fmt.Errorf("manifest start block ID: %w", err)
		}
		expectedStart, _ := parseHash32(anchor.StartBlockID)
		if startID != expectedStart {
			return fmt.Errorf("manifest start block ID does not match approved checkpoint")
		}
		startState, err := parseHash32(manifest.StartStateRoot)
		if err != nil {
			return fmt.Errorf("manifest start state root: %w", err)
		}
		expectedStartState, _ := parseHash32(anchor.StartStateRoot)
		if startState != expectedStartState {
			return fmt.Errorf("manifest start state root does not match approved checkpoint")
		}
	}
	blockID, err := parseHash32(manifest.AnchorBlockID)
	if err != nil {
		return fmt.Errorf("manifest anchor block ID: %w", err)
	}
	expectedBlock, _ := parseHash32(anchor.AnchorBlockID)
	if blockID != expectedBlock {
		return fmt.Errorf("manifest anchor block ID does not match approved anchor")
	}
	stateRoot, err := parseHash32(manifest.AnchorStateRoot)
	if err != nil {
		return fmt.Errorf("manifest state root: %w", err)
	}
	expectedState, _ := parseHash32(anchor.AnchorStateRoot)
	if stateRoot != expectedState {
		return fmt.Errorf("manifest state root does not match approved anchor")
	}
	if _, err := parseSHA256(manifest.BlocksSHA256); err != nil {
		return fmt.Errorf("manifest blocks_sha256: %w", err)
	}
	if _, err := parseSHA256(manifest.BodiesSHA256); err != nil {
		return fmt.Errorf("manifest bodies_sha256: %w", err)
	}
	return nil
}

func verifyManifestSignature(root string, manifestBytes []byte, approved ApprovedSource) ([32]byte, [32]byte, error) {
	var signatureHash, publicKeyHash [32]byte
	publicKey, err := parsePublicKey(approved.SigningPublicKey)
	if err != nil {
		return signatureHash, publicKeyHash, err
	}
	signaturePath := filepath.Join(root, SignatureName)
	signatureText, err := readRegularFile(signaturePath, MaxSignatureSize)
	if err != nil {
		return signatureHash, publicKeyHash, fmt.Errorf("read %s: %w", SignatureName, err)
	}
	if bytes.HasSuffix(signatureText, []byte("\r\n")) {
		signatureText = signatureText[:len(signatureText)-2]
	} else if bytes.HasSuffix(signatureText, []byte("\n")) {
		signatureText = signatureText[:len(signatureText)-1]
	}
	if len(signatureText) != hex.EncodedLen(ed25519.SignatureSize) || string(signatureText) != strings.ToLower(string(signatureText)) {
		return signatureHash, publicKeyHash, fmt.Errorf("%s is not canonical lowercase Ed25519 signature hex", SignatureName)
	}
	signature, err := hex.DecodeString(string(signatureText))
	if err != nil {
		return signatureHash, publicKeyHash, fmt.Errorf("decode %s: %w", SignatureName, err)
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		return signatureHash, publicKeyHash, fmt.Errorf("manifest signature is invalid for the approved source key")
	}
	return sha256.Sum256(signature), sha256.Sum256(publicKey), nil
}
