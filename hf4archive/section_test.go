package hf4archive

import (
	"strings"
	"testing"
)

const (
	testSectionStartID    = "1313131313131313131313131313131313131313131313131313131313131313"
	testSectionStartState = "1414141414141414141414141414141414141414141414141414141414141414"
)

func sectionInput() bundleInput {
	in := defaultInput()
	tx1 := strings.Repeat("01", 32)
	tx2 := strings.Repeat("02", 32)
	tx3 := strings.Repeat("03", 32)
	body1 := []byte("body-one")
	body2 := []byte("body-two")
	body3 := []byte("body-three")
	in.firstTopo = 100
	in.startBlockID = testSectionStartID
	in.startStateRoot = testSectionStartState
	in.archiveID = "archive-section-a"
	in.blocks = []BlockRow{
		{TopoHeight: 100, BlockHash: testSectionStartID, TransactionHashes: []string{}},
		{TopoHeight: 101, BlockHash: strings.Repeat("a1", 32), TransactionHashes: []string{tx1}},
		{TopoHeight: 102, BlockHash: testAnchorID, TransactionHashes: []string{tx2, tx3}},
	}
	in.bodies = []BodyRow{
		{TopoHeight: 101, TransactionIndex: 0, TransactionHash: tx1, BodySHA256: hashHex(body1), BodySize: uint64(len(body1))},
		{TopoHeight: 102, TransactionIndex: 0, TransactionHash: tx2, BodySHA256: hashHex(body2), BodySize: uint64(len(body2))},
		{TopoHeight: 102, TransactionIndex: 1, TransactionHash: tx3, BodySHA256: hashHex(body3), BodySize: uint64(len(body3))},
	}
	in.bodyByTx = map[string][]byte{tx1: body1, tx2: body2, tx3: body3}
	return in
}

func TestSectionBundleValid(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, sectionInput())
	bundle := mustOpen(t, dir, approved, anchor)
	if bundle.Summary.FirstTopoHeight != 100 || bundle.Summary.StartBlockID != testSectionStartID {
		t.Fatalf("unexpected section summary: %+v", bundle.Summary)
	}
	if bundle.Summary.Blocks != 3 || bundle.Summary.Transactions != 3 {
		t.Fatalf("unexpected section counts: %+v", bundle.Summary)
	}
}

func TestSectionRequiresStartStateRoot(t *testing.T) {
	in := sectionInput()
	in.startStateRoot = ""
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, in)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "start state root") {
		t.Fatalf("expected start state root failure, got %v", err)
	}
}

func TestSectionRequiresStartBlockID(t *testing.T) {
	in := sectionInput()
	in.startBlockID = ""
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, in)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "start block ID") {
		t.Fatalf("expected start block ID failure, got %v", err)
	}
}

func TestSectionStartBlockMustMatchApproval(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, sectionInput())
	anchor.StartBlockID = strings.Repeat("ff", 32)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "start block ID does not match approved checkpoint") {
		t.Fatalf("expected start block mismatch, got %v", err)
	}
}

func TestSectionStartStateMustMatchApproval(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, sectionInput())
	anchor.StartStateRoot = strings.Repeat("ff", 32)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "start state root does not match approved checkpoint") {
		t.Fatalf("expected start state mismatch, got %v", err)
	}
}

func TestSectionRejectsGenesisField(t *testing.T) {
	dir := t.TempDir()
	in := sectionInput()
	approved, anchor := writeBundle(t, dir, in)
	manifest := loadManifest(t, dir)
	manifest.GenesisBlockID = testGenesisID
	resignManifest(t, dir, manifest, in.seed)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "section archive must not carry a genesis block ID") {
		t.Fatalf("expected section genesis-field failure, got %v", err)
	}
}

func TestGenesisRejectsSectionFields(t *testing.T) {
	dir := t.TempDir()
	in := defaultInput()
	approved, anchor := writeBundle(t, dir, in)
	manifest := loadManifest(t, dir)
	manifest.StartBlockID = testSectionStartID
	manifest.StartStateRoot = testSectionStartState
	resignManifest(t, dir, manifest, in.seed)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "genesis archive must not carry section start fields") {
		t.Fatalf("expected genesis section-field failure, got %v", err)
	}
}

func TestSectionTopoGapIsRejected(t *testing.T) {
	in := sectionInput()
	in.blocks = append(in.blocks[:1], in.blocks[2:]...)
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, in)
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Fatalf("expected section gap failure, got %v", err)
	}
}

func TestSectionStartAboveAnchorIsRejected(t *testing.T) {
	dir := t.TempDir()
	approved, anchor := writeBundle(t, dir, sectionInput())
	anchor.FirstTopoHeight = 103
	if _, err := OpenBundle(dir, approved, testNetwork, anchor); err == nil || !strings.Contains(err.Error(), "exceeds anchor topo height") {
		t.Fatalf("expected start-above-anchor failure, got %v", err)
	}
}

func TestSectionPairAgreement(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	inA := sectionInput()
	inB := sectionInput()
	inB.archiveID = "archive-section-b"
	inB.sourceID = "source-b"
	inB.operatorID = "operator-b"
	inB.seed = 8
	approvedA, anchor := writeBundle(t, dirA, inA)
	approvedB, _ := writeBundle(t, dirB, inB)
	pair, err := VerifyPair(
		BundleSpec{Dir: dirA, Approved: approvedA, ExpectedNetwork: testNetwork, Anchor: anchor},
		BundleSpec{Dir: dirB, Approved: approvedB, ExpectedNetwork: testNetwork, Anchor: anchor},
	)
	if err != nil {
		t.Fatalf("VerifyPair section: %v", err)
	}
	if pair.FirstTopoHeight != 100 || pair.StartBlockID != testSectionStartID || pair.StartStateRoot != testSectionStartState {
		t.Fatalf("unexpected section pair summary: %+v", pair)
	}
	if pair.Transactions != 3 || len(pair.Sources) != 2 {
		t.Fatalf("unexpected section pair counts: %+v", pair)
	}
}

func TestSectionPairRejectsStartStateMismatch(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	inA := sectionInput()
	inB := sectionInput()
	inB.archiveID = "archive-section-b"
	inB.sourceID = "source-b"
	inB.operatorID = "operator-b"
	inB.seed = 8
	inB.startStateRoot = "1515151515151515151515151515151515151515151515151515151515151515"
	approvedA, anchor := writeBundle(t, dirA, inA)
	approvedB, _ := writeBundle(t, dirB, inB)
	if _, err := VerifyPair(
		BundleSpec{Dir: dirA, Approved: approvedA, ExpectedNetwork: testNetwork, Anchor: anchor},
		BundleSpec{Dir: dirB, Approved: approvedB, ExpectedNetwork: testNetwork, Anchor: anchor},
	); err == nil || !strings.Contains(err.Error(), "start state root does not match approved checkpoint") {
		t.Fatalf("expected section pair start-state failure, got %v", err)
	}
}
