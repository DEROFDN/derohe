package hf4archive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testNetwork   = "mainnet"
	testGenesisID = "1010101010101010101010101010101010101010101010101010101010101010"
	testAnchorID  = "1111111111111111111111111111111111111111111111111111111111111111"
	testStateRoot = "1212121212121212121212121212121212121212121212121212121212121212"
)

type bundleInput struct {
	blocks         []BlockRow
	bodies         []BodyRow
	bodyByTx       map[string][]byte
	network        string
	archiveID      string
	sourceID       string
	operatorID     string
	seed           byte
	firstTopo      uint64
	startBlockID   string
	startStateRoot string
}

func defaultInput() bundleInput {
	tx1 := strings.Repeat("01", 32)
	tx2 := strings.Repeat("02", 32)
	tx3 := strings.Repeat("03", 32)
	body1 := []byte("body-one")
	body2 := []byte("body-two")
	body3 := []byte("body-three")
	return bundleInput{
		network:    testNetwork,
		archiveID:  "archive-a",
		sourceID:   "source-a",
		operatorID: "operator-a",
		seed:       7,
		blocks: []BlockRow{
			{TopoHeight: 0, BlockHash: testGenesisID, TransactionHashes: []string{}},
			{TopoHeight: 1, BlockHash: strings.Repeat("a1", 32), TransactionHashes: []string{tx1}},
			{TopoHeight: 2, BlockHash: testAnchorID, TransactionHashes: []string{tx2, tx3}},
		},
		bodies: []BodyRow{
			{TopoHeight: 1, TransactionIndex: 0, TransactionHash: tx1, BodySHA256: hashHex(body1), BodySize: uint64(len(body1))},
			{TopoHeight: 2, TransactionIndex: 0, TransactionHash: tx2, BodySHA256: hashHex(body2), BodySize: uint64(len(body2))},
			{TopoHeight: 2, TransactionIndex: 1, TransactionHash: tx3, BodySHA256: hashHex(body3), BodySize: uint64(len(body3))},
		},
		bodyByTx: map[string][]byte{tx1: body1, tx2: body2, tx3: body3},
	}
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeBundle(t *testing.T, dir string, in bundleInput) (ApprovedSource, Anchor) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, TxDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	for tx, body := range in.bodyByTx {
		txDir := filepath.Join(dir, TxDirName, tx)
		if err := os.MkdirAll(txDir, 0o755); err != nil {
			t.Fatal(err)
		}
		name := hashHex(body) + ".hex"
		if err := os.WriteFile(filepath.Join(txDir, name), []byte(hex.EncodeToString(body)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	blocksBytes := encodeRows(t, in.blocks)
	bodiesBytes := encodeRows(t, in.bodies)
	if err := os.WriteFile(filepath.Join(dir, BlocksName), blocksBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BodiesName), bodiesBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	var through uint64
	if len(in.blocks) > 0 {
		through = in.blocks[len(in.blocks)-1].TopoHeight
	}
	manifest := Manifest{
		SchemaVersion:     SchemaVersion,
		Network:           in.network,
		ArchiveID:         in.archiveID,
		SourceID:          in.sourceID,
		OperatorID:        in.operatorID,
		CollectionCommand: "derod export --test-fixture",
		Endpoint:          "https://example.org/archive",
		SourceCommit:      strings.Repeat("ab", 20),
		FirstTopoHeight:   in.firstTopo,
		ThroughTopoHeight: through,
		AnchorBlockID:     testAnchorID,
		AnchorStateRoot:   testStateRoot,
		BlocksSHA256:      hashHex(blocksBytes),
		BodiesSHA256:      hashHex(bodiesBytes),
	}
	if in.firstTopo == 0 {
		manifest.GenesisBlockID = testGenesisID
	} else {
		manifest.StartBlockID = in.startBlockID
		manifest.StartStateRoot = in.startStateRoot
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{in.seed}, ed25519.SeedSize))
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, manifestBytes)
	if err := os.WriteFile(filepath.Join(dir, SignatureName), []byte(hex.EncodeToString(signature)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	anchor := Anchor{
		FirstTopoHeight:   in.firstTopo,
		AnchorBlockID:     testAnchorID,
		AnchorStateRoot:   testStateRoot,
		ThroughTopoHeight: through,
	}
	if in.firstTopo == 0 {
		anchor.GenesisBlockID = testGenesisID
	} else {
		anchor.StartBlockID = in.startBlockID
		anchor.StartStateRoot = in.startStateRoot
	}
	return ApprovedSource{
		SourceID:         in.sourceID,
		OperatorID:       in.operatorID,
		SigningPublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
	}, anchor
}

func encodeRows(t *testing.T, rows interface{}) []byte {
	t.Helper()
	var out bytes.Buffer
	switch value := rows.(type) {
	case []BlockRow:
		for _, row := range value {
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			out.Write(data)
			out.WriteByte('\n')
		}
	case []BodyRow:
		for _, row := range value {
			data, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			out.Write(data)
			out.WriteByte('\n')
		}
	default:
		t.Fatalf("unsupported row type %T", rows)
	}
	return out.Bytes()
}

func mustOpen(t *testing.T, dir string, approved ApprovedSource, anchor Anchor) *Bundle {
	t.Helper()
	bundle, err := OpenBundle(dir, approved, testNetwork, anchor)
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	return bundle
}

func TestOpenBundleValid(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, defaultInput())
	bundle := mustOpen(t, dir, approved, anchor)
	if bundle.Summary.Blocks != 3 || bundle.Summary.Transactions != 3 {
		t.Fatalf("unexpected summary: %+v", bundle.Summary)
	}
	if bundle.Summary.BodyBytes != uint64(len("body-one")+len("body-two")+len("body-three")) {
		t.Fatalf("unexpected body bytes: %d", bundle.Summary.BodyBytes)
	}
	if bundle.Summary.ThroughTopoHeight != 2 {
		t.Fatalf("unexpected through height: %d", bundle.Summary.ThroughTopoHeight)
	}
}

func TestManifestSignatureIsRequired(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, defaultInput())
	signaturePath := filepath.Join(dir, SignatureName)
	data, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	if err := os.WriteFile(signaturePath, []byte(hex.EncodeToString(raw)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestManifestMustBeCanonical(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, defaultInput())
	manifestPath := filepath.Join(dir, ManifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("expected canonical failure, got %v", err)
	}
}

func TestBlocksHashMismatch(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, defaultInput())
	path := filepath.Join(dir, BlocksName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "SHA-256 does not match") {
		t.Fatalf("expected blocks hash failure, got %v", err)
	}
}

func TestBodyFileTamper(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	approved, anchor := writeBundle(t, dir, in)
	tx1 := strings.Repeat("01", 32)
	path := filepath.Join(dir, TxDirName, tx1, hashHex(in.bodyByTx[tx1])+".hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString([]byte("body-ONE"))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected body hash failure, got %v", err)
	}
}

func TestMissingBodyFile(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	approved, anchor := writeBundle(t, dir, in)
	tx2 := strings.Repeat("02", 32)
	path := filepath.Join(dir, TxDirName, tx2, hashHex(in.bodyByTx[tx2])+".hex")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "read transaction body") {
		t.Fatalf("expected missing body failure, got %v", err)
	}
}

func TestTopoOrderIsEnforced(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	in.blocks[2].TopoHeight = 3
	in.bodies[1].TopoHeight = 3
	in.bodies[2].TopoHeight = 3
	approved, anchor := writeBundle(t, dir, in)
	anchor.ThroughTopoHeight = 3
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Fatalf("expected order failure, got %v", err)
	}
}

func TestBodyCatalogMismatch(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	in.bodies[2].TransactionHash = strings.Repeat("09", 32)
	approved, anchor := writeBundle(t, dir, in)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "does not match the block catalog") {
		t.Fatalf("expected body catalog failure, got %v", err)
	}
}

func TestNetworkAndIdentityMustMatchApproval(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	in.network = "testnet"
	approved, anchor := writeBundle(t, dir, in)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "network mismatch") {
		t.Fatalf("expected network failure, got %v", err)
	}

	dir = t.TempDir()
	in = defaultInput()
	in.sourceID = "source-imposter"
	approved, anchor = writeBundle(t, dir, in)
	approved.SourceID = "source-a"
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "does not match explicit approval") {
		t.Fatalf("expected identity failure, got %v", err)
	}
}

func TestAnchorMustMatch(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, defaultInput())
	anchor.AnchorBlockID = strings.Repeat("ff", 32)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "anchor block ID") {
		t.Fatalf("expected anchor failure, got %v", err)
	}
}

func TestPrivateEndpointIsRejected(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	approved, anchor := writeBundle(t, dir, in)
	manifestPath := filepath.Join(dir, ManifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Endpoint = "http://127.0.0.1:8080/archive"
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "private or internal") {
		t.Fatalf("expected endpoint failure, got %v", err)
	}
}

func TestVerifyPairAgreement(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	inA := defaultInput()
	inB := defaultInput()
	inB.archiveID = "archive-b"
	inB.sourceID = "source-b"
	inB.operatorID = "operator-b"
	inB.seed = 8
	approvedA, _ := writeBundle(t, dirA, inA)
	approvedB, anchor := writeBundle(t, dirB, inB)
	pair, err := VerifyPair(
		BundleSpec{Dir: dirA, Approved: approvedA, ExpectedNetwork: testNetwork, Anchor: anchor},
		BundleSpec{Dir: dirB, Approved: approvedB, ExpectedNetwork: testNetwork, Anchor: anchor},
	)
	if err != nil {
		t.Fatalf("VerifyPair: %v", err)
	}
	if pair.Transactions != 3 || pair.BlocksSHA256 == "" || len(pair.Sources) != 2 {
		t.Fatalf("unexpected pair summary: %+v", pair)
	}
}

func TestVerifyPairRejectsSameIdentity(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	inA := defaultInput()
	inB := defaultInput()
	inB.archiveID = "archive-b"
	inB.seed = 8
	approvedA, _ := writeBundle(t, dirA, inA)
	approvedB, anchor := writeBundle(t, dirB, inB)
	if _, err := VerifyPair(
		BundleSpec{Dir: dirA, Approved: approvedA, ExpectedNetwork: testNetwork, Anchor: anchor},
		BundleSpec{Dir: dirB, Approved: approvedB, ExpectedNetwork: testNetwork, Anchor: anchor},
	); err == nil || !strings.Contains(err.Error(), "distinct sources and operators") {
		t.Fatalf("expected distinct identity failure, got %v", err)
	}
}

func TestVerifyPairRejectsDifferentCatalogs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	inA := defaultInput()
	inB := defaultInput()
	inB.archiveID = "archive-b"
	inB.sourceID = "source-b"
	inB.operatorID = "operator-b"
	inB.seed = 8
	inB.bodyByTx[strings.Repeat("02", 32)] = []byte("body-two-changed")
	inB.bodies[1].BodySHA256 = hashHex(inB.bodyByTx[strings.Repeat("02", 32)])
	inB.bodies[1].BodySize = uint64(len(inB.bodyByTx[strings.Repeat("02", 32)]))
	approvedA, _ := writeBundle(t, dirA, inA)
	approvedB, anchor := writeBundle(t, dirB, inB)
	if _, err := VerifyPair(
		BundleSpec{Dir: dirA, Approved: approvedA, ExpectedNetwork: testNetwork, Anchor: anchor},
		BundleSpec{Dir: dirB, Approved: approvedB, ExpectedNetwork: testNetwork, Anchor: anchor},
	); err == nil || !strings.Contains(err.Error(), "catalogs differ") {
		t.Fatalf("expected catalog mismatch, got %v", err)
	}
}

func TestSummaryIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, defaultInput())
	first := mustOpen(t, dir, approved, anchor).Summary
	second := mustOpen(t, dir, approved, anchor).Summary
	if fmt.Sprintf("%+v", first) != fmt.Sprintf("%+v", second) {
		t.Fatalf("summary is not deterministic")
	}
}
