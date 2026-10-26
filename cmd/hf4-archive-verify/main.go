// Command hf4-archive-verify validates signed HF4 supply-archive bundles.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/deroproject/derohe/hf4archive"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify-one":
		runVerifyOne(os.Args[2:])
	case "verify-pair":
		runVerifyPair(os.Args[2:])
	case "canonicalize":
		runCanonicalize(os.Args[2:])
	case "template":
		runTemplate(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hf4-archive-verify validates signed HF4 supply-archive bundles.

Usage:
  # Genesis-to-anchor prefix
  hf4-archive-verify verify-one -dir <bundle> -source-id <id> -operator-id <id> \
    -pubkey <ed25519-hex> -genesis-block <hash> -anchor-block <hash> \
    -anchor-state-root <hash> -anchor-topo <n> [-network mainnet]

  # Checkpoint-to-anchor section (trusted start checkpoint)
  hf4-archive-verify verify-one -dir <bundle> -source-id <id> -operator-id <id> \
    -pubkey <ed25519-hex> -first-topo <n> -start-block <hash> -start-state-root <hash> \
    -anchor-block <hash> -anchor-state-root <hash> -anchor-topo <n> [-network mainnet]

  hf4-archive-verify verify-pair \
    -a-dir <bundle> -a-source-id <id> -a-operator-id <id> -a-pubkey <ed25519-hex> \
    -b-dir <bundle> -b-source-id <id> -b-operator-id <id> -b-pubkey <ed25519-hex> \
    (-genesis-block <hash> | -first-topo <n> -start-block <hash> -start-state-root <hash>) \
    -anchor-block <hash> -anchor-state-root <hash> -anchor-topo <n> [-network mainnet]

  hf4-archive-verify canonicalize -manifest <file>
  hf4-archive-verify template

verify-one and verify-pair print a JSON summary and exit non-zero on failure.
`)
}

func runVerifyOne(args []string) {
	fs := flag.NewFlagSet("verify-one", flag.ExitOnError)
	dir := fs.String("dir", "", "archive bundle directory")
	network := fs.String("network", "mainnet", "expected network")
	sourceID := fs.String("source-id", "", "approved source ID")
	operatorID := fs.String("operator-id", "", "approved operator ID")
	pubkey := fs.String("pubkey", "", "approved Ed25519 public key, lowercase hex")
	genesis := fs.String("genesis-block", "", "approved genesis block ID (first-topo 0)")
	firstTopo := fs.Uint64("first-topo", 0, "first topo height (0 for a genesis prefix)")
	startBlock := fs.String("start-block", "", "approved section start block ID (first-topo > 0)")
	startState := fs.String("start-state-root", "", "approved section start state root (first-topo > 0)")
	anchorBlock := fs.String("anchor-block", "", "approved anchor block ID")
	anchorState := fs.String("anchor-state-root", "", "approved anchor state root")
	anchorTopo := fs.Uint64("anchor-topo", 0, "approved anchor topo height")
	_ = fs.Parse(args)
	requireFlags(map[string]string{
		"-dir": *dir, "-source-id": *sourceID, "-operator-id": *operatorID,
		"-pubkey": *pubkey, "-anchor-block": *anchorBlock,
		"-anchor-state-root": *anchorState,
	})
	requireExplicit(fs, "anchor-topo")
	anchor := buildAnchor(*firstTopo, *genesis, *startBlock, *startState, *anchorBlock, *anchorState, *anchorTopo)

	bundle, err := hf4archive.OpenBundle(*dir, hf4archive.ApprovedSource{
		SourceID: *sourceID, OperatorID: *operatorID, SigningPublicKey: *pubkey,
	}, *network, anchor)
	if err != nil {
		fail(err)
	}
	printJSON(map[string]interface{}{"ok": true, "bundle": bundle.Summary})
}

func runVerifyPair(args []string) {
	fs := flag.NewFlagSet("verify-pair", flag.ExitOnError)
	aDir := fs.String("a-dir", "", "archive A directory")
	aSource := fs.String("a-source-id", "", "archive A approved source ID")
	aOperator := fs.String("a-operator-id", "", "archive A approved operator ID")
	aPubkey := fs.String("a-pubkey", "", "archive A approved Ed25519 public key")
	bDir := fs.String("b-dir", "", "archive B directory")
	bSource := fs.String("b-source-id", "", "archive B approved source ID")
	bOperator := fs.String("b-operator-id", "", "archive B approved operator ID")
	bPubkey := fs.String("b-pubkey", "", "archive B approved Ed25519 public key")
	network := fs.String("network", "mainnet", "expected network")
	genesis := fs.String("genesis-block", "", "approved genesis block ID (first-topo 0)")
	firstTopo := fs.Uint64("first-topo", 0, "first topo height (0 for a genesis prefix)")
	startBlock := fs.String("start-block", "", "approved section start block ID (first-topo > 0)")
	startState := fs.String("start-state-root", "", "approved section start state root (first-topo > 0)")
	anchorBlock := fs.String("anchor-block", "", "approved anchor block ID")
	anchorState := fs.String("anchor-state-root", "", "approved anchor state root")
	anchorTopo := fs.Uint64("anchor-topo", 0, "approved anchor topo height")
	_ = fs.Parse(args)
	requireFlags(map[string]string{
		"-a-dir": *aDir, "-a-source-id": *aSource, "-a-operator-id": *aOperator, "-a-pubkey": *aPubkey,
		"-b-dir": *bDir, "-b-source-id": *bSource, "-b-operator-id": *bOperator, "-b-pubkey": *bPubkey,
		"-anchor-block": *anchorBlock, "-anchor-state-root": *anchorState,
	})
	requireExplicit(fs, "anchor-topo")
	anchor := buildAnchor(*firstTopo, *genesis, *startBlock, *startState, *anchorBlock, *anchorState, *anchorTopo)

	pair, err := hf4archive.VerifyPair(
		hf4archive.BundleSpec{
			Dir:             *aDir,
			Approved:        hf4archive.ApprovedSource{SourceID: *aSource, OperatorID: *aOperator, SigningPublicKey: *aPubkey},
			ExpectedNetwork: *network,
			Anchor:          anchor,
		},
		hf4archive.BundleSpec{
			Dir:             *bDir,
			Approved:        hf4archive.ApprovedSource{SourceID: *bSource, OperatorID: *bOperator, SigningPublicKey: *bPubkey},
			ExpectedNetwork: *network,
			Anchor:          anchor,
		},
	)
	if err != nil {
		fail(err)
	}
	printJSON(map[string]interface{}{"ok": true, "pair": pair})
}

func runCanonicalize(args []string) {
	fs := flag.NewFlagSet("canonicalize", flag.ExitOnError)
	path := fs.String("manifest", "", "manifest JSON file")
	_ = fs.Parse(args)
	if *path == "" {
		fmt.Fprintln(os.Stderr, "-manifest is required")
		os.Exit(2)
	}
	info, err := os.Stat(*path)
	if err != nil {
		fail(err)
	}
	if info.Size() > hf4archive.MaxManifestSize {
		fail(fmt.Errorf("manifest exceeds the %d-byte limit", hf4archive.MaxManifestSize))
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		fail(err)
	}
	var manifest hf4archive.Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		fail(fmt.Errorf("decode manifest: %w", err))
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		fail(fmt.Errorf("manifest has trailing JSON data"))
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		fail(err)
	}
	if _, err := os.Stdout.Write(canonical); err != nil {
		fail(err)
	}
}

func runTemplate(args []string) {
	fs := flag.NewFlagSet("template", flag.ExitOnError)
	_ = fs.Parse(args)
	manifest := hf4archive.Manifest{
		SchemaVersion:     hf4archive.SchemaVersion,
		Network:           "mainnet",
		ArchiveID:         "community-archive-001",
		SourceID:          "community-node-a",
		OperatorID:        "operator-a",
		CollectionCommand: "replace with the exact command used to export the archive",
		Endpoint:          "https://example.org/dero-archive",
		SourceCommit:      strings.Repeat("0", 40),
		FirstTopoHeight:   0,
		ThroughTopoHeight: 123456,
		GenesisBlockID:    strings.Repeat("0", 64),
		AnchorBlockID:     strings.Repeat("0", 64),
		AnchorStateRoot:   strings.Repeat("0", 64),
		BlocksSHA256:      strings.Repeat("0", 64),
		BodiesSHA256:      strings.Repeat("0", 64),
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fail(err)
	}
	os.Stdout.Write(data)
	os.Stdout.Write([]byte("\n"))
}

func buildAnchor(firstTopo uint64, genesis, startBlock, startState, anchorBlock, anchorState string, anchorTopo uint64) hf4archive.Anchor {
	anchor := hf4archive.Anchor{
		FirstTopoHeight:   firstTopo,
		AnchorBlockID:     anchorBlock,
		AnchorStateRoot:   anchorState,
		ThroughTopoHeight: anchorTopo,
	}
	if firstTopo == 0 {
		if strings.TrimSpace(genesis) == "" {
			usageError("-genesis-block is required when -first-topo is 0")
		}
		if strings.TrimSpace(startBlock) != "" || strings.TrimSpace(startState) != "" {
			usageError("-start-block and -start-state-root require -first-topo greater than 0")
		}
		anchor.GenesisBlockID = genesis
		return anchor
	}
	if strings.TrimSpace(genesis) != "" {
		usageError("-genesis-block must be empty when -first-topo is greater than 0")
	}
	if strings.TrimSpace(startBlock) == "" || strings.TrimSpace(startState) == "" {
		usageError("-start-block and -start-state-root are required when -first-topo is greater than 0")
	}
	anchor.StartBlockID = startBlock
	anchor.StartStateRoot = startState
	return anchor
}

func usageError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func requireFlags(values map[string]string) {
	for name, value := range values {
		if strings.TrimSpace(value) == "" {
			fmt.Fprintf(os.Stderr, "%s is required\n", name)
			os.Exit(2)
		}
	}
}

func requireExplicit(fs *flag.FlagSet, name string) {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	if !set {
		fmt.Fprintf(os.Stderr, "-%s is required\n", name)
		os.Exit(2)
	}
}

func printJSON(value interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
