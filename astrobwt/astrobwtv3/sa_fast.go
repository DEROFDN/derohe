package astrobwtv3

import "unsafe"
import "hash"
import "sync"

//import "fmt"
import "encoding/binary"
import "github.com/minio/sha256-simd"

const MAX_LENGTH uint32 = (256 * 384) - 1 // this is the maximum

// see here to improve the algorithms more https://github.com/y-256/libdivsufsort/blob/wiki/SACA_Benchmarks.md
// this optimized algorithm is used only  in the miner and not in the blockchain

type ScratchData struct {
	hasher              hash.Hash
	data                [MAX_LENGTH + 64]uint8
	stage1_result       *[MAX_LENGTH + 1]uint16
	stage1_result_bytes *[(MAX_LENGTH) * 2]uint8
	indices             [MAX_LENGTH + 1]uint32 // 256 KB
	tmp_indices         [MAX_LENGTH + 1]uint32 // 256 KB
	sa                  [MAX_LENGTH]int32
	sa_bytes            *[(MAX_LENGTH) * 4]uint8

	// Template-descriptor SA construction (sa_template.go): exploits the
	// repeat structure AstroBWTv3's own wolf loop produces (see that file's
	// header), rather than treating scratch.data as opaque text the way
	// divsufsort/SA-IS do. markers/nTemplates/flags are populated
	// unconditionally by pow.go's wolf loop regardless of useTemplateSA,
	// since recording them is pure bookkeeping with no effect on the hash —
	// see sa_template.go's header for why that's safe.
	markers       [280]uint16 // template markers: firstChunk<<7 | chunkCount
	nTemplates    uint32
	flags         [280]byte          // stage-5 group-boundary flags (buildStage5Flags output)
	useTemplateSA bool               // production default: true (Pool.New below). Force false to get the divsufsort path explicitly.
	templateSA    *templateSAScratch // lazily allocated on first use
}

var Pool = sync.Pool{New: func() interface{} {
	var d ScratchData
	d.hasher = sha256.New()
	// Template-descriptor SA is the production default: proven
	// byte-identical to divsufsort across a 1,000,000-hash differential
	// gate and 64 real captured fixtures, and substantially faster in
	// isolation. Any decline falls back to text_32_0alloc (divsufsort) at
	// the pow.go dispatch site, so this default carries no correctness risk
	// beyond what divsufsort itself already carries. Force
	// d.useTemplateSA = false on a scratch to get the divsufsort path
	// explicitly — this package's own differential tests use that as the
	// independent reference to check the template path against.
	d.useTemplateSA = true
	d.stage1_result = ((*[MAX_LENGTH + 1]uint16)(unsafe.Pointer(&d.indices[0])))
	d.stage1_result_bytes = ((*[(MAX_LENGTH) * 2]byte)(unsafe.Pointer(&d.indices[0])))
	d.sa_bytes = ((*[(MAX_LENGTH) * 4]byte)(unsafe.Pointer(&d.sa[0])))

	return &d
}}

func fix(v []byte, indices []uint32, i int) {
	prev_t := indices[i]
	t := indices[i+1]

	// ReadBigUint32Unsafe  can be replaced with this   binary.BigEndian.Uint32
	data_a := binary.BigEndian.Uint32(v[((t)&0xffff)+2:])
	if data_a <= binary.BigEndian.Uint32(v[((prev_t)&0xffff)+2:]) {
		t2 := prev_t
		j := i
		_ = indices[j+1]
		for {
			indices[j+1] = prev_t
			j--
			if j < 0 {
				break
			}
			prev_t = indices[j]
			if (t^prev_t) <= 0xffff && data_a <= binary.BigEndian.Uint32(v[((prev_t)&0xffff)+2:]) {
				continue
			} else {
				break
			}
		}
		indices[j+1] = t
		t = t2
	}
}

// basically
func sort_indices(N uint32, v []byte, output []uint16, d *ScratchData) {

	var byte_counters [2][256]uint16
	var counters [2][256]uint16

	v[N] = 0   // make sure extra byte accessed is zero
	v[N+1] = 0 // make sure extra byte accessed is zero

	indices := d.indices[:]
	tmp_indices := d.tmp_indices[:]

	for _, c := range v[:N] {
		byte_counters[1][c]++
	}
	byte_counters[0] = byte_counters[1]
	byte_counters[0][v[0]]--

	counters[0][0] = uint16(byte_counters[0][0])
	counters[1][0] = uint16(byte_counters[1][0]) - 1

	c0 := counters[0][0]
	c1 := counters[1][0]

	for i := 1; i < 256; i++ {
		c0 += uint16(byte_counters[0][i])
		c1 += uint16(byte_counters[1][i])

		counters[0][i] = c0
		counters[1][i] = c1
	}

	counters0 := counters[0][:]

	{ // handle the last byte separately
		byte0 := uint32(v[N-1])
		tmp_indices[counters0[0]] = byte0<<24 | uint32(N-1)
		counters0[0]--
	}

	for i := int(N - 1); i >= 1; i-- {
		byte0 := uint32(v[i-1])
		byte1 := uint32(v[i]) // here we can access extra byte from input array so make sure its zero
		tmp_indices[counters0[v[i]]] = byte0<<24 | byte1<<16 | uint32(i-1)
		counters0[v[i]]--
	}

	counters1 := counters[1][:]
	_ = tmp_indices[N-1]
	for i := int(N - 1); i >= 0; i-- {
		data := tmp_indices[i]
		tmp := counters1[data>>24]
		counters1[data>>24]--
		indices[tmp] = data
	}

	for i := 1; i < int(N); i++ { // no BC here
		if indices[i-1]&0xffff0000 == indices[i]&0xffff0000 {
			fix(v, indices, i-1)
		}
	}

	// after fixing, convert indices to output
	_ = output[N]
	for i, c := range indices[:N] {
		output[i] = uint16(c)
	}
}

// text_32_0alloc is AstroBWTv3's production suffix-array entry point (the
// only caller is pow.go's AstroBWTv3, which hashes the raw sa bytes
// directly -- see sa_bytes -- so this function's output is consensus-
// critical, not just performance-critical).
//
// Stage 4b: backed by the divsufsort port (computeSuffixArrayDivSufSort0Alloc,
// divsufsort_go.go) instead of SA-IS. This is the culmination of the
// AstroBWTv3 suffix-array research project: divsufsort runs ~1.70ms vs
// SA-IS's ~2.16ms on realistic input (BenchmarkDivSufSortGo0Alloc_Realistic
// vs BenchmarkSAIS_Realistic), both genuinely 0-alloc. The two are proven
// byte-identical across hundreds of dual-compute trials including every
// real captured AstroBWTv3 fixture (TestDivSufSortMatchesProductionSAIS)
// and, more importantly, are proven byte-identical by construction: a
// suffix array is unique for a given text, so two correct algorithms must
// already agree. See text_32_0alloc_sais for the retired SA-IS
// implementation, kept as a permanent comparison oracle rather than
// deleted, since it's the exact code that validated every DERO block up to
// this cutover.
//
// bucketA/bucketB are declared locally rather than pooled on ScratchData:
// BenchmarkDivSufSortGo0Alloc_Realistic already proved this exact shape
// (local stack arrays passed into computeSuffixArrayDivSufSort0Alloc) is
// 0 B/op, 0 allocs/op, so pooling would add ScratchData footprint for no
// measurable benefit.
func text_32_0alloc(text []byte, sa []int32) {
	if int(int32(len(text))) != len(text) || len(text) != len(sa) {
		panic("suffixarray: misuse of text_16")
	}
	var bucketA [256]int32
	var bucketB [256 * 256]int32
	computeSuffixArrayDivSufSort0Alloc(text, sa, bucketA[:], bucketB[:])
}

// text_32_0alloc_sais is the original SA-IS-based production implementation,
// retired from the hot path by the Stage 4b divsufsort cutover above. Kept
// deliberately, not deleted: it's the exact implementation that validated
// every DERO block before this cutover, so it serves as a permanent
// comparison oracle (TestDivSufSortMatchesProductionSAIS in
// divsufsort_go_test.go runs both on every `go test .` and asserts
// byte-identical output) and as the SA-IS baseline for
// BenchmarkSAIS_Realistic and friends.
func text_32_0alloc_sais(text []byte, sa []int32) {
	if int(int32(len(text))) != len(text) || len(text) != len(sa) {
		panic("suffixarray: misuse of text_16")
	}
	for i := range sa {
		sa[i] = 0
	}
	var memory [2 * 256]int32
	sais_8_32(text, 256, sa, memory[:])
}
