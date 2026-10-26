package hf4archive

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// BundleSpec identifies one archive and its out-of-band approvals.
type BundleSpec struct {
	Dir             string
	Approved        ApprovedSource
	ExpectedNetwork string
	Anchor          Anchor
}

// PairSummary describes two bundles that independently agree on the catalog.
type PairSummary struct {
	Network           string    `json:"network"`
	FirstTopoHeight   uint64    `json:"first_topo_height"`
	GenesisBlockID    string    `json:"genesis_block_id,omitempty"`
	StartBlockID      string    `json:"start_block_id,omitempty"`
	StartStateRoot    string    `json:"start_state_root,omitempty"`
	AnchorBlockID     string    `json:"anchor_block_id"`
	AnchorStateRoot   string    `json:"anchor_state_root"`
	ThroughTopoHeight uint64    `json:"through_topo_height"`
	BlocksSHA256      string    `json:"blocks_sha256"`
	BodiesSHA256      string    `json:"bodies_sha256"`
	Transactions      uint64    `json:"transactions"`
	BodyBytes         uint64    `json:"body_bytes"`
	Sources           []Summary `json:"sources"`
}

// VerifyPair authenticates two independently pinned archives and requires exact
// catalog agreement. It does not establish operator independence or archive
// truth; those remain review decisions.
func VerifyPair(a, b BundleSpec) (*PairSummary, error) {
	if a.ExpectedNetwork == "" || b.ExpectedNetwork == "" {
		return nil, fmt.Errorf("expected network must be set for both archives")
	}
	if a.ExpectedNetwork != b.ExpectedNetwork {
		return nil, fmt.Errorf("archive networks differ")
	}
	if err := validateDistinctDirs(a.Dir, b.Dir); err != nil {
		return nil, err
	}
	if err := validatePairApprovals(a.Approved, b.Approved); err != nil {
		return nil, err
	}
	if a.Anchor != b.Anchor {
		return nil, fmt.Errorf("approved anchors differ")
	}

	first, err := OpenBundle(a.Dir, a.Approved, a.ExpectedNetwork, a.Anchor)
	if err != nil {
		return nil, fmt.Errorf("archive A: %w", err)
	}
	second, err := OpenBundle(b.Dir, b.Approved, b.ExpectedNetwork, b.Anchor)
	if err != nil {
		return nil, fmt.Errorf("archive B: %w", err)
	}

	if first.Manifest.ArchiveID == second.Manifest.ArchiveID {
		return nil, fmt.Errorf("archive IDs are not distinct")
	}
	if first.Manifest.Network != second.Manifest.Network {
		return nil, fmt.Errorf("manifest networks differ")
	}
	if first.Manifest.FirstTopoHeight != second.Manifest.FirstTopoHeight {
		return nil, fmt.Errorf("archive first heights differ")
	}
	if first.Manifest.StartBlockID != second.Manifest.StartBlockID || first.Manifest.StartStateRoot != second.Manifest.StartStateRoot {
		return nil, fmt.Errorf("archive start checkpoints differ")
	}
	if first.Manifest.ThroughTopoHeight != second.Manifest.ThroughTopoHeight {
		return nil, fmt.Errorf("archive through heights differ")
	}
	if first.BlocksSHA256 != second.BlocksSHA256 {
		return nil, fmt.Errorf("blocks.jsonl catalogs differ")
	}
	if first.BodiesSHA256 != second.BodiesSHA256 {
		return nil, fmt.Errorf("bodies.jsonl catalogs differ")
	}
	if first.Summary.Transactions != second.Summary.Transactions || first.Summary.Blocks != second.Summary.Blocks || first.Summary.BodyBytes != second.Summary.BodyBytes {
		return nil, fmt.Errorf("archive summaries differ")
	}

	return &PairSummary{
		Network:           first.Manifest.Network,
		FirstTopoHeight:   first.Manifest.FirstTopoHeight,
		GenesisBlockID:    first.Manifest.GenesisBlockID,
		StartBlockID:      first.Manifest.StartBlockID,
		StartStateRoot:    first.Manifest.StartStateRoot,
		AnchorBlockID:     first.Manifest.AnchorBlockID,
		AnchorStateRoot:   first.Manifest.AnchorStateRoot,
		ThroughTopoHeight: first.Manifest.ThroughTopoHeight,
		BlocksSHA256:      fmt.Sprintf("%x", first.BlocksSHA256),
		BodiesSHA256:      fmt.Sprintf("%x", first.BodiesSHA256),
		Transactions:      first.Summary.Transactions,
		BodyBytes:         first.Summary.BodyBytes,
		Sources:           []Summary{first.Summary, second.Summary},
	}, nil
}

func validateDistinctDirs(a, b string) error {
	if a == "" || b == "" {
		return fmt.Errorf("both archive directories are required")
	}
	aAbs, err := filepath.Abs(a)
	if err != nil {
		return fmt.Errorf("resolve archive A: %w", err)
	}
	bAbs, err := filepath.Abs(b)
	if err != nil {
		return fmt.Errorf("resolve archive B: %w", err)
	}
	aInfo, err := os.Stat(aAbs)
	if err != nil {
		return fmt.Errorf("stat archive A: %w", err)
	}
	bInfo, err := os.Stat(bAbs)
	if err != nil {
		return fmt.Errorf("stat archive B: %w", err)
	}
	if filepath.Clean(aAbs) == filepath.Clean(bAbs) || os.SameFile(aInfo, bInfo) {
		return fmt.Errorf("archive paths must resolve to distinct directories")
	}
	return nil
}

func validatePairApprovals(a, b ApprovedSource) error {
	if a.SourceID == "" || a.OperatorID == "" || b.SourceID == "" || b.OperatorID == "" {
		return fmt.Errorf("both archive sources and operators must be explicitly approved")
	}
	if a.SourceID == b.SourceID || a.OperatorID == b.OperatorID {
		return fmt.Errorf("archive approvals must name distinct sources and operators")
	}
	aKey, err := parsePublicKey(a.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("archive A signing public key: %w", err)
	}
	bKey, err := parsePublicKey(b.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("archive B signing public key: %w", err)
	}
	if bytes.Equal(aKey, bKey) {
		return fmt.Errorf("archive approvals must pin distinct signing public keys")
	}
	return nil
}
