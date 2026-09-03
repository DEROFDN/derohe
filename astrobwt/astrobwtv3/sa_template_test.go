package astrobwtv3

// Tests for the template-descriptor SA path (sa_template.go), organized
// bottom-up: the flag builder in isolation, Stage 4 (emit) against
// synthetic buffers, Stage 5 (merge) against hand-built descriptor
// records, a hand-built end-to-end run against the divsufsort oracle, wolf-
// loop marker bookkeeping, and finally the full differential/gate suite
// against AstroBWTv3's real production dispatch.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ---- buildStage5Flags, isolated ----

func TestBuildStage5FlagsZeroTemplates(t *testing.T) {
	// nTemplates == 0: the loop body never runs, so only flags[0] is set.
	var flags [280]byte
	logicalLen := uint32(256 * 3)
	got := buildStage5Flags(nil, 0, logicalLen, flags[:])
	want := uint32(4) // (768>>8)+1
	if got != want {
		t.Fatalf("flagsLen = %d, want %d", got, want)
	}
	for i := uint32(0); i < got; i++ {
		wantBit := byte(0)
		if i == 0 {
			wantBit = 1
		}
		if flags[i] != wantBit {
			t.Errorf("flags[%d] = %d, want %d", i, flags[i], wantBit)
		}
	}
}

func TestBuildStage5FlagsOneTemplateSpansWholeBuffer(t *testing.T) {
	// One template: firstChunk=0, chunkCount=5, covering all 5 groups of a
	// 1280-byte buffer.
	markers := []uint16{0<<7 | 5}
	var flags [280]byte
	logicalLen := uint32(256 * 5)
	flagsLen := buildStage5Flags(markers, 1, logicalLen, flags[:])
	if flagsLen != 6 { // (1280>>8)+1
		t.Fatalf("flagsLen = %d, want 6", flagsLen)
	}
	want := [6]byte{1, 0, 0, 0, 0, 1} // boundary at startGroup(0)+groupCount(5)=5
	for i := 0; i < 6; i++ {
		if flags[i] != want[i] {
			t.Errorf("flags[%d] = %d, want %d", i, flags[i], want[i])
		}
	}
}

func TestBuildStage5FlagsManySingleChunkTemplates(t *testing.T) {
	// 4 templates, each spanning exactly one chunk: boundaries at 1,2,3,4.
	markers := []uint16{
		0<<7 | 1,
		1<<7 | 1,
		2<<7 | 1,
		3<<7 | 1,
	}
	var flags [280]byte
	logicalLen := uint32(256 * 4)
	flagsLen := buildStage5Flags(markers, 4, logicalLen, flags[:])
	if flagsLen != 5 {
		t.Fatalf("flagsLen = %d, want 5", flagsLen)
	}
	for i := 0; i < 5; i++ {
		if flags[i] != 1 {
			t.Errorf("flags[%d] = %d, want 1 (every boundary set)", i, flags[i])
		}
	}
}

func TestBuildStage5FlagsOutOfRangeBoundaryDropped(t *testing.T) {
	// A marker whose boundary lands at or past flagsLen must be silently
	// ignored (no out-of-bounds write, no panic) — this is the real-world
	// case of data_len truncating up to ~1KiB off the wolf loop's raw
	// tries*256 stream, so a recorded template can reference chunks past
	// what the final logicalLen covers.
	markers := []uint16{0<<7 | 5} // boundary = 5
	var flags [280]byte
	logicalLen := uint32(256 * 2) // flagsLen = 3; boundary 5 >= 3, must be dropped
	flagsLen := buildStage5Flags(markers, 1, logicalLen, flags[:])
	if flagsLen != 3 {
		t.Fatalf("flagsLen = %d, want 3", flagsLen)
	}
	want := [3]byte{1, 0, 0}
	for i := 0; i < 3; i++ {
		if flags[i] != want[i] {
			t.Errorf("flags[%d] = %d, want %d (out-of-range boundary must not be set)", i, flags[i], want[i])
		}
	}
}

func TestBuildStage5FlagsZeroGroupCountSkipped(t *testing.T) {
	// A marker with groupCount==0 must not set any boundary (explicit
	// groupCount != 0 guard).
	markers := []uint16{0<<7 | 0}
	var flags [280]byte
	logicalLen := uint32(256 * 2)
	flagsLen := buildStage5Flags(markers, 1, logicalLen, flags[:])
	if flagsLen != 3 {
		t.Fatalf("flagsLen = %d, want 3", flagsLen)
	}
	want := [3]byte{1, 0, 0}
	for i := 0; i < 3; i++ {
		if flags[i] != want[i] {
			t.Errorf("flags[%d] = %d, want %d", i, flags[i], want[i])
		}
	}
}

func TestBuildStage5FlagsDeclinesOnZeroLogicalLen(t *testing.T) {
	var flags [280]byte
	if got := buildStage5Flags(nil, 0, 0, flags[:]); got != 0 {
		t.Fatalf("buildStage5Flags(logicalLen=0) = %d, want 0", got)
	}
}

func TestBuildStage5FlagsDeclinesOnUndersizedFlags(t *testing.T) {
	flags := make([]byte, 2) // flagsLen for logicalLen=768 is 4; flags is too short
	if got := buildStage5Flags(nil, 0, 256*3, flags); got != 0 {
		t.Fatalf("buildStage5Flags(undersized flags) = %d, want 0", got)
	}
}

// ---- Stage 4 (emit), isolated ----

// verifyStage4Emission checks the three properties that make Stage 4's
// output trustworthy input for Stage 5, without needing Stage 5 itself:
//  1. coverage — every position in [base, base+groupCount*256) is emitted
//     exactly once (no drops, no duplicates);
//  2. key correctness — every emitted record's stored key equals the real
//     3-byte prefix at its position(s), read directly from view.data;
//  3. intra-run order — for any multi-position (arena) run, its positions
//     are already in true full-suffix order (compareSuffixes, the same real
//     oracle emit.go itself uses), which is the non-obvious invariant Stage
//     5's tryWriteTwoRuns/mergeEqualKeyRuns depend on (see sa_template.go's
//     header: the very first full sort at column 255 establishes true
//     order, and every later stable re-sort by an additional prefix byte
//     can only ever preserve it within a narrower matching bucket).
func verifyStage4Emission(t *testing.T, view *stage4View, base, groupCount uint32, v *templateSAScratch) {
	t.Helper()
	total := groupCount * 256
	seen := make([]bool, total)
	for _, r := range v.runs {
		count := r.count()
		var positions []uint32
		if r.isLiteral() {
			positions = []uint32{r.begin()}
		} else {
			begin := r.begin()
			positions = append(positions, v.arena[begin:begin+count]...)
		}
		for i, pos := range positions {
			if pos < base || pos >= base+total {
				t.Fatalf("emitted position %d out of range [%d,%d)", pos, base, base+total)
			}
			rel := pos - base
			if seen[rel] {
				t.Fatalf("position %d emitted more than once", pos)
			}
			seen[rel] = true

			key := uint32(view.data[pos]) | uint32(view.data[pos+1])<<8 | uint32(view.data[pos+2])<<16
			if key != r.key {
				t.Fatalf("position %d: stored key %#x != real 3-byte prefix %#x", pos, r.key, key)
			}
			if i > 0 {
				prev := positions[i-1]
				if compareSuffixes(view, prev, pos) > 0 {
					t.Fatalf("arena run not in true suffix order: position %d should sort before %d", pos, prev)
				}
			}
		}
	}
	for rel, ok := range seen {
		if !ok {
			t.Fatalf("position %d never emitted (dropped)", base+uint32(rel))
		}
	}
}

func TestEmitFullGroupRunSizes(t *testing.T) {
	rng := rand.New(rand.NewSource(20260803))
	sizes := []uint32{1, 2, 24, 25, 26, stage4MaxGroupRun}
	for _, gc := range sizes {
		gc := gc
		t.Run(sizeLabel(gc), func(t *testing.T) {
			n := int(gc) * 256
			data := genUniformRandom(rng, n)
			data = append(data, 0, 0, 0, 0) // key-load padding, buildTemplateSA's own contract
			view := &stage4View{data: data, logicalLen: uint32(n)}
			v := newTemplateSAScratch()
			if !emitFullGroupRun(view, 0, gc, v) {
				t.Fatalf("emitFullGroupRun declined for groupCount=%d", gc)
			}
			verifyStage4Emission(t, view, 0, gc, v)
		})
	}
}

func TestEmitFullGroupRunDeclinesAboveMax(t *testing.T) {
	gc := uint32(stage4MaxGroupRun) + 1
	n := int(gc) * 256
	data := make([]byte, n+4) // content doesn't matter, decline happens before any read
	view := &stage4View{data: data, logicalLen: uint32(n)}
	v := newTemplateSAScratch()
	if emitFullGroupRun(view, 0, gc, v) {
		t.Fatalf("emitFullGroupRun accepted groupCount=%d, want decline (> stage4MaxGroupRun=%d)", gc, stage4MaxGroupRun)
	}
}

func sizeLabel(gc uint32) string {
	switch gc {
	case 1:
		return "1chunk"
	case 2:
		return "2chunks"
	case 24:
		return "24_below_short_run_max"
	case 25:
		return "25_at_short_run_max"
	case 26:
		return "26_above_short_run_max"
	default:
		return "max_group_run"
	}
}

// ---- Stage 5 (merge), isolated: hand-built descriptor records ----

// TestWriteFusedRunsToSACascadePaths hand-builds v.runs/v.arena to exercise
// every cascade path in writeFusedRunsToSA within a single call: a
// singleton-literal group, a singleton-arena group (one run, but that run's
// own count > 1), a 2-run tie (tryWriteTwoRuns), a 32-run all-literal tie
// (tryWriteLiteralGroup's own cap), and a 33-run tie (forces
// mergeEqualKeyRuns, since it's neither <=32-all-literal nor exactly 2
// runs). Each zone gets its own key (ascending across zones, so output
// blocks land in known order) and each zone's positions carry an
// ascending distinguishing byte at pos+3, so real suffix order within a
// zone is simply ascending member index — letting the test assert exact
// expected output per zone without re-deriving a full suffix sort.
func TestWriteFusedRunsToSACascadePaths(t *testing.T) {
	const stride = 50
	zoneSizes := []int{1, 5, 2, 32, 33}
	totalPositions := 0
	for _, n := range zoneSizes {
		totalPositions += n
	}

	bufLen := totalPositions*stride + 4
	data := make([]byte, bufLen)
	for i := range data {
		data[i] = 0xAA // background filler, distinct from any zone key byte below
	}

	type zonePos struct {
		pos []uint32
	}
	zones := make([]zonePos, len(zoneSizes))
	posIdx := 0
	for zi, n := range zoneSizes {
		key := uint32(0x100000 + zi*0x1000) // distinct, ascending across zones
		for m := 0; m < n; m++ {
			p := uint32(posIdx * stride)
			data[p] = byte(key)
			data[p+1] = byte(key >> 8)
			data[p+2] = byte(key >> 16)
			data[p+3] = byte(m) // ascending distinguishing byte -> ascending true order
			zones[zi].pos = append(zones[zi].pos, p)
			posIdx++
		}
	}

	view := &stage4View{data: data, logicalLen: uint32(bufLen - 4)}
	v := newTemplateSAScratch()

	// Zone 0 (size 1): singleton literal run.
	v.runs = append(v.runs, stage5Run{key: 0x100000, packed: zones[0].pos[0]})

	// Zone 1 (size 5): singleton run whose own count > 1 (arena-backed) —
	// members already in ascending (true) order, matching what Stage 4's
	// induction would have produced.
	begin := uint32(len(v.arena))
	v.arena = append(v.arena, zones[1].pos...)
	v.runs = append(v.runs, stage5Run{key: 0x101000, packed: 5<<17 + begin})

	// Zone 2 (size 2): two literal runs sharing a key -> tryWriteTwoRuns.
	v.runs = append(v.runs,
		stage5Run{key: 0x102000, packed: zones[2].pos[0]},
		stage5Run{key: 0x102000, packed: zones[2].pos[1]})

	// Zone 3 (size 32): 32 literal runs sharing a key -> tryWriteLiteralGroup.
	for _, p := range zones[3].pos {
		v.runs = append(v.runs, stage5Run{key: 0x103000, packed: p})
	}

	// Zone 4 (size 33): 33 literal runs sharing a key -> exceeds
	// tryWriteLiteralGroup's 32 cap and isn't exactly 2 runs, so
	// mergeEqualKeyRuns must handle it.
	for _, p := range zones[4].pos {
		v.runs = append(v.runs, stage5Run{key: 0x104000, packed: p})
	}

	sa := make([]int32, totalPositions)
	if !writeFusedRunsToSA(view, v, sa) {
		t.Fatalf("writeFusedRunsToSA declined")
	}

	out := 0
	for zi, z := range zones {
		for m, wantPos := range z.pos {
			if int(sa[out]) != int(wantPos) {
				t.Errorf("zone %d member %d: sa[%d] = %d, want %d", zi, m, out, sa[out], wantPos)
			}
			out++
		}
	}
}

// ---- End-to-end buildTemplateSA, hand-built templates ----

// buildHandTemplateSAScratch builds a *ScratchData with a 3-template layout
// (sizes 1/2/5 chunks = 8 chunks = 2048 bytes total) over deterministic
// random text, ready for buildTemplateSA.
func buildHandTemplateSAScratch(t *testing.T) (*ScratchData, []byte, uint32) {
	t.Helper()
	rng := rand.New(rand.NewSource(20260803))
	const logicalLen = 8 * 256
	text := genUniformRandom(rng, logicalLen)

	scratch := Pool.Get().(*ScratchData)
	copy(scratch.data[:logicalLen], text)
	scratch.markers[0] = 0<<7 | 1 // template 0: chunk [0,1)
	scratch.markers[1] = 1<<7 | 2 // template 1: chunks [1,3)
	scratch.markers[2] = 3<<7 | 5 // template 2: chunks [3,8)
	scratch.nTemplates = 3
	return scratch, text, logicalLen
}

func TestBuildTemplateSAMatchesProductionDivSufSort(t *testing.T) {
	scratch, text, logicalLen := buildHandTemplateSAScratch(t)
	defer Pool.Put(scratch)

	if !buildTemplateSA(scratch, logicalLen) {
		t.Fatalf("buildTemplateSA declined on a well-formed 3-template input")
	}

	want := make([]int32, logicalLen)
	computeSuffixArrayDivSufSort(append([]byte(nil), text...), want)

	got := scratch.sa[:logicalLen]
	if !equalInt32(got, want) {
		t.Fatalf("buildTemplateSA output != computeSuffixArrayDivSufSort output")
	}
}

func TestBuildTemplateSAPoisonedPaddingBufferReuse(t *testing.T) {
	scratch, text, logicalLen := buildHandTemplateSAScratch(t)
	defer Pool.Put(scratch)

	// Poison the 4-byte key-load padding zone with stale/adversarial data,
	// simulating a sync.Pool-reused scratch whose previous hash left garbage
	// there. buildTemplateSA must zero it itself, unconditionally.
	scratch.data[logicalLen] = 0xff
	scratch.data[logicalLen+1] = 0xff
	scratch.data[logicalLen+2] = 0xff
	scratch.data[logicalLen+3] = 0xff

	if !buildTemplateSA(scratch, logicalLen) {
		t.Fatalf("buildTemplateSA declined on a well-formed 3-template input")
	}

	want := make([]int32, logicalLen)
	computeSuffixArrayDivSufSort(append([]byte(nil), text...), want)

	got := scratch.sa[:logicalLen]
	if !equalInt32(got, want) {
		t.Fatalf("buildTemplateSA output affected by poisoned padding — zero-pad must be unconditional")
	}
}

func TestBuildTemplateSADeclinesOnZeroTemplates(t *testing.T) {
	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)
	scratch.nTemplates = 0
	if buildTemplateSA(scratch, 256) {
		t.Fatalf("buildTemplateSA accepted nTemplates=0, want decline")
	}
}

func TestBuildTemplateSADeclinesOnZeroLogicalLen(t *testing.T) {
	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)
	scratch.markers[0] = 0<<7 | 1
	scratch.nTemplates = 1
	if buildTemplateSA(scratch, 0) {
		t.Fatalf("buildTemplateSA accepted logicalLen=0, want decline")
	}
}

// ---- Wolf-loop marker bookkeeping, structural sanity ----

// TestWolfLoopMarkersStructurallyConsistent runs the real, unmodified wolf
// loop (via astroBWTv3) and checks properties that must hold for any real
// run, regardless of the exact RC4-whitening schedule: nTemplates is within
// the protocol's own tries<=277 bound, and each recorded template's decoded
// firstChunk is non-decreasing across markers[0:nTemplates] — every write
// to markers[k] happens at the "tries" value current at that moment, and
// tries only ever increases, so later indices (and later writes to the
// same index, from the tries>1 first-flush behavior) can only ever record
// an equal-or-later firstChunk, never an earlier one.
func TestWolfLoopMarkersStructurallyConsistent(t *testing.T) {
	rng := rand.New(rand.NewSource(20260803))
	for trial := 0; trial < 200; trial++ {
		input := genUniformRandom(rng, 48)
		scratch := Pool.Get().(*ScratchData)
		astroBWTv3(input, scratch)

		if scratch.nTemplates == 0 || scratch.nTemplates > 277 {
			t.Fatalf("trial %d: nTemplates = %d, want in [1,277]", trial, scratch.nTemplates)
		}
		lastFirstChunk := uint32(0)
		for i := uint32(0); i < scratch.nTemplates; i++ {
			firstChunk := uint32(scratch.markers[i]) >> 7
			if i > 0 && firstChunk < lastFirstChunk {
				t.Fatalf("trial %d: markers[%d] firstChunk=%d < markers[%d] firstChunk=%d (must be non-decreasing)",
					trial, i, firstChunk, i-1, lastFirstChunk)
			}
			lastFirstChunk = firstChunk
		}
		Pool.Put(scratch)
	}
}

// ---- Production dispatch: differential and fixture round-trip ----

// TestTemplateSADispatchMatchesProductionKAT checks AstroBWTv3's real
// production output (the template path by default, see sa_fast.go's
// Pool.New) against the divsufsort path, forced explicitly via
// scratch.useTemplateSA = false, on this package's own existing KAT inputs
// (pow_test.go's random_pow_tests) — not the hardcoded hex vectors, which
// TestAstroBWTv3 already covers; this test's job is differential between
// the two SA algorithms specifically.
func TestTemplateSADispatchMatchesProductionKAT(t *testing.T) {
	for i := range random_pow_tests {
		in := []byte(random_pow_tests[i].in)

		refScratch := Pool.Get().(*ScratchData)
		refScratch.useTemplateSA = false
		want := astroBWTv3(in, refScratch)
		Pool.Put(refScratch)

		got := AstroBWTv3(in) // production = template path by default

		if got != want {
			t.Fatalf("input %q: production (template) = %x, want (divsufsort reference) %x", in, got, want)
		}
	}
}

// saTemplateFixtureDirForTest duplicates the path used by the (build-tag-
// gated) generator (sa_template_fixture_gen_test.go's saTemplateFixtureDir)
// rather than referencing its constant, so this file compiles and runs in
// a normal (non astrobwt_capture) build — mirrors sais_bench_test.go's own
// saFixtureDirForBench convention.
const saTemplateFixtureDirForTest = "testdata/safixtures_template"

// TestTemplateSAFixtureRoundTrip loads every (data, markers, input)
// fixture triple from testdata/safixtures_template (see
// sa_template_fixture_gen_test.go) and checks two independent things per
// fixture: (1) buildTemplateSA on the captured data/markers matches this
// package's own divsufsort oracle on the same data — the primary
// correctness check, self-contained and not dependent on re-running
// anything; (2) a fresh, fully re-run wolf loop over the fixture's
// original 48-byte seed input agrees between production (template path)
// and the divsufsort reference — proving the captured markers are
// faithful to a real run, not just internally self-consistent.
func TestTemplateSAFixtureRoundTrip(t *testing.T) {
	entries, err := os.ReadDir(saTemplateFixtureDirForTest)
	if err != nil {
		t.Skipf("no template SA fixtures (%v); run: go test -tags astrobwt_capture -run TestGenerateSATemplateFixtures -v .", err)
	}

	count := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "data_") || filepath.Ext(name) != ".bin" {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimPrefix(name, "data_"), ".bin")
		parts := strings.SplitN(rest, "_", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected fixture filename %s", name)
		}
		dataLenStr, idx := parts[0], parts[1]
		dataLen, err := strconv.Atoi(dataLenStr)
		if err != nil {
			t.Fatalf("fixture %s: bad dataLen: %v", name, err)
		}

		data, err := os.ReadFile(filepath.Join(saTemplateFixtureDirForTest, name))
		if err != nil {
			t.Fatalf("fixture %s: read data: %v", name, err)
		}
		markersRaw, err := os.ReadFile(filepath.Join(saTemplateFixtureDirForTest, fmt.Sprintf("markers_%s_%s.bin", dataLenStr, idx)))
		if err != nil {
			t.Fatalf("fixture %s: read markers: %v", name, err)
		}
		inputRaw, err := os.ReadFile(filepath.Join(saTemplateFixtureDirForTest, fmt.Sprintf("input_%s_%s.bin", dataLenStr, idx)))
		if err != nil {
			t.Fatalf("fixture %s: read input: %v", name, err)
		}

		nTemplates := len(markersRaw) / 2
		markers := make([]uint16, nTemplates)
		for i := range markers {
			markers[i] = binary.LittleEndian.Uint16(markersRaw[i*2:])
		}

		// (1) buildTemplateSA on the captured data/markers vs. the
		// divsufsort oracle on the same data.
		scratch := Pool.Get().(*ScratchData)
		copy(scratch.data[:dataLen], data)
		copy(scratch.markers[:], markers)
		scratch.nTemplates = uint32(nTemplates)
		if !buildTemplateSA(scratch, uint32(dataLen)) {
			t.Fatalf("fixture %s: buildTemplateSA declined on a real captured fixture", name)
		}
		want := make([]int32, dataLen)
		computeSuffixArrayDivSufSort(append([]byte(nil), data...), want)
		if !equalInt32(scratch.sa[:dataLen], want) {
			t.Fatalf("fixture %s: buildTemplateSA output != divsufsort oracle", name)
		}
		Pool.Put(scratch)

		// (2) a fully fresh run (real wolf loop, not replayed bytes) of the
		// original seed agrees between production (template path) and the
		// divsufsort reference — complements (1), which only replays
		// already-captured data/markers.
		refScratch := Pool.Get().(*ScratchData)
		refScratch.useTemplateSA = false
		wantHash := astroBWTv3(inputRaw, refScratch)
		Pool.Put(refScratch)

		gotHash := AstroBWTv3(inputRaw) // production = template path by default
		if gotHash != wantHash {
			t.Fatalf("fixture %s: fresh production (template) run != divsufsort reference", name)
		}

		count++
	}
	if count == 0 {
		t.Skip("no template SA fixtures found")
	}
	t.Logf("round-tripped %d template SA fixtures", count)
}

// TestTemplateSADifferentialVsProduction runs many random 48-byte (real
// protocol input size) hashes through AstroBWTv3 (template path by
// default, sa_fast.go's Pool.New) and checks byte-for-byte agreement with
// the divsufsort reference path, forced explicitly via
// scratch.useTemplateSA = false.
func TestTemplateSADifferentialVsProduction(t *testing.T) {
	n := 5000
	if testing.Short() {
		n = 300
	}
	rng := rand.New(rand.NewSource(20260803))
	refScratch := Pool.Get().(*ScratchData)
	refScratch.useTemplateSA = false
	defer Pool.Put(refScratch)

	for i := 0; i < n; i++ {
		input := genUniformRandom(rng, 48)
		want := astroBWTv3(input, refScratch)
		got := AstroBWTv3(input) // production = template path by default
		if got != want {
			t.Fatalf("trial %d: input %x: production (template) = %x, want (divsufsort reference) %x", i, input, got, want)
		}
	}
}

// TestTemplateSADifferentialLengths checks byte-for-byte agreement across
// input lengths beyond the real protocol's fixed 48 bytes, since
// AstroBWTv3 itself accepts arbitrary []byte.
func TestTemplateSADifferentialLengths(t *testing.T) {
	lengths := []int{1, 2, 3, 7, 16, 31, 47, 48, 49, 64, 255, 1024}
	rng := rand.New(rand.NewSource(20260803))
	refScratch := Pool.Get().(*ScratchData)
	refScratch.useTemplateSA = false
	defer Pool.Put(refScratch)

	for _, n := range lengths {
		input := genUniformRandom(rng, n)
		want := astroBWTv3(input, refScratch)
		got := AstroBWTv3(input) // production = template path by default
		if got != want {
			t.Fatalf("length %d: production (template) = %x, want (divsufsort reference) %x", n, got, want)
		}
	}
}

// TestTemplateSAFallbackRate checks the decline rate stays under the same
// 10% observability ceiling the reference port's own gate uses.
func TestTemplateSAFallbackRate(t *testing.T) {
	const n = 500
	rng := rand.New(rand.NewSource(20260803))
	scratch := Pool.Get().(*ScratchData)
	scratch.useTemplateSA = true
	defer Pool.Put(scratch)

	before := templateSAFallbacks.Load()
	for i := 0; i < n; i++ {
		input := genUniformRandom(rng, 48)
		astroBWTv3(input, scratch)
	}
	fell := templateSAFallbacks.Load() - before
	rate := float64(fell) / float64(n) * 100
	t.Logf("template SA fallback rate: %d/%d (%.2f%%)", fell, n, rate)
	if fell > n/10 {
		t.Fatalf("fallback rate %.2f%% exceeds the 10%% ceiling", rate)
	}
}

// TestTemplateSAZeroAllocsAfterWarmup: after one warmup call (which lazily
// allocates scratch.templateSA, sa_template.go), buildTemplateSA itself
// must be exactly 0 allocs/op, and no fallback may occur during the
// measured run.
//
// Scoped to buildTemplateSA directly (the SA-construction stage), not the
// whole astroBWTv3 pipeline: a plain testing.AllocsPerRun around
// astroBWTv3 shows 1-2 allocs/op regardless of useTemplateSA — overhead
// elsewhere in the wolf-loop/hasher body, unrelated to SA construction, and
// out of scope here. Only buildTemplateSA's own 0-alloc property matters,
// matching BenchmarkTemplateSAStageOnly_Realistic's identical scope in
// sa_template_bench_test.go.
func TestTemplateSAZeroAllocsAfterWarmup(t *testing.T) {
	rng := rand.New(rand.NewSource(20260803))
	const dataLen = 66048 // 258 * 256, a realistic mid-range data_len
	data := genUniformRandom(rng, dataLen)
	data = append(data, 0, 0, 0, 0)

	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)
	copy(scratch.data[:dataLen], data)
	// A handful of evenly-sized templates covering the whole buffer.
	const chunksPerTemplate = 6
	fullChunks := uint32(dataLen) >> 8
	templateIdx := 0
	for start := uint32(0); start < fullChunks; start += chunksPerTemplate {
		count := chunksPerTemplate
		if start+chunksPerTemplate > fullChunks {
			count = int(fullChunks - start)
		}
		scratch.markers[templateIdx] = uint16(start<<7 | uint32(count))
		templateIdx++
	}
	scratch.nTemplates = uint32(templateIdx)

	if !buildTemplateSA(scratch, dataLen) {
		t.Fatalf("buildTemplateSA declined during warmup")
	} // warmup: lazily allocates scratch.templateSA

	before := templateSAFallbacks.Load()
	allocs := testing.AllocsPerRun(100, func() {
		if !buildTemplateSA(scratch, dataLen) {
			t.Fatalf("buildTemplateSA declined during the measured run")
		}
	})
	after := templateSAFallbacks.Load()

	if allocs != 0 {
		t.Fatalf("buildTemplateSA allocated %.1f allocs/op after warmup, want 0", allocs)
	}
	if after != before {
		t.Fatalf("templateSAFallbacks moved by %d during the measured run — a fallback occurred, allocs figure is not trustworthy", after-before)
	}
}
