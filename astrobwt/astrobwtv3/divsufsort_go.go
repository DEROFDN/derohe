package astrobwtv3

// Stage 3 of a staged clean-room Go port of libdivsufsort's algorithm shape
// (Yuta Mori, MIT license; unmodified C reference is at
// assets/tnn-miner/src/crypto/astrobwtv3/divsufsort.c). NOT wired into any
// production code path -- reachable only from this package's own
// tests/benchmarks. See the project plan for the staging rationale.
//
// divsufsort classifies every suffix as type A (what SA-IS calls L-type),
// type B (S-type), or type B* (an S-run start immediately following an
// L-run -- what SA-IS calls an LMS position), then:
//  1. fully sorts the type B* suffixes,
//  2. induces every other suffix's position from that sorted B* order.
//
// The induction step (dsInduceSuffixArray, mirroring construct_SA) only
// ever consumes a correctly and fully ordered list of B*-suffix text
// positions -- it has no dependency on *how* that order was produced.
//
// Milestone 1 sorted the B* suffixes with a placeholder full-comparison
// sort. Milestone 2 (sssort_go.go) replaced that with a real port of
// divsufsort's sssort: bounded-depth multikey-quicksort + block-merge,
// bucketed by first two characters exactly as divsufsort.c does (lines
// ~98-148). sssort's comparison depth is bounded by the *next* B*-suffix's
// position (it sorts substrings, not full suffixes), so it cannot resolve
// every tie by itself; Milestone 2 fell back to a full-suffix comparison
// for whatever sssort left undetermined. Milestone 3 (trsort_go.go)
// replaced that fallback with a real port of divsufsort's trsort: the
// Larsson-Sadakane tandem-repeat rank-doubling sort real divsufsort uses
// to resolve those same ties in O(m log m), no unbounded suffix
// comparisons. See sais_bench_test.go's BenchmarkDivSufSortGo_Realistic
// for the honest current number.
//
// The placement and induction logic below (dsPlaceBStarSuffixes,
// dsInduceSuffixArray) is unchanged since Milestone 1: a faithful, close
// translation of divsufsort.c's "set sorted order of type B* suffixes" /
// "move to correct position" / construct_SA (~lines 168-260), preserved
// deliberately close to the original control flow and index arithmetic
// rather than "cleaned up", since matching the reference's exact behavior
// is what matters here.

// bucketBIndex/bucketBStarIndex mirror divsufsort_private.h's BUCKET_B/
// BUCKET_BSTAR macros: both are views over the SAME underlying 256*256
// array with swapped index order (BUCKET_B(c0,c1) = bucket_B[c1*256+c0],
// BUCKET_BSTAR(c0,c1) = bucket_B[c0*256+c1]) -- this aliasing is load-
// bearing in the original algorithm (the two views are used at different
// points to store different data in the same backing storage), so both
// helpers operate on one shared bucketB slice, never separate ones.
func bucketBIndex(c0, c1 int) int     { return c1*256 + c0 }
func bucketBStarIndex(c0, c1 int) int { return c0*256 + c1 }

// dsClassifyAndCount is a close translation of divsufsort.c's
// sort_typeBstar, lines ~66-79: a single backward scan over text
// classifying every position as type A, B, or B*, counting first/first-two-
// character occurrences into bucketA/bucketB, and storing every type B*
// suffix's text position into sa, filled from the end backward (so after
// this call, sa[n-m:n] holds the B*-suffix positions -- referred to as PAb
// below, matching the C source's naming). Returns m, the number of type B*
// suffixes found.
func dsClassifyAndCount(text []byte, sa []int32, bucketA, bucketB []int32) int {
	n := len(text)
	m := n
	i := n - 1
	c0 := int(text[n-1])

	for i >= 0 {
		// type A run (do-while in C: body executes at least once).
		var c1 int
		for {
			c1 = c0
			bucketA[c1]++
			i--
			if i < 0 {
				break
			}
			c0 = int(text[i])
			if c0 < c1 {
				break
			}
		}
		if i < 0 {
			break
		}

		// position i is a type B* suffix.
		bucketB[bucketBStarIndex(c0, c1)]++
		m--
		sa[m] = int32(i)

		// type B run: consume the rest of this S-run.
		i--
		c1 = c0
		for i >= 0 {
			c0 = int(text[i])
			if c0 > c1 {
				break
			}
			bucketB[bucketBIndex(c0, c1)]++
			c1 = c0
			i--
		}
	}
	return n - m
}

// dsComputeBucketOffsets is a direct translation of divsufsort.c's bucket
// start/end offset computation, lines ~87-96. Converts the raw counts
// dsClassifyAndCount produced into cumulative start points (bucketA) and
// end points (bucketB, in its B* view).
func dsComputeBucketOffsets(bucketA, bucketB []int32) {
	var i, j int32
	for c0 := 0; c0 < 256; c0++ {
		t := i + bucketA[c0]
		bucketA[c0] = i + j
		i = t + bucketB[bucketBIndex(c0, c0)]
		for c1 := c0 + 1; c1 < 256; c1++ {
			j += bucketB[bucketBStarIndex(c0, c1)]
			bucketB[bucketBStarIndex(c0, c1)] = j
			i += bucketB[bucketBIndex(c0, c1)]
		}
	}
}

// dsBucketBStarSuffixes is a real port of divsufsort.c's "Sort the type B*
// suffixes by their first two characters" step (lines ~98-106): buckets
// every B*-suffix's compact index into sa[0:m] by (c0,c1), consuming
// BUCKET_BSTAR's end-point offsets down to start-points as it goes. This
// supersedes Milestone 1's dsBucketBStarPointers, which only replicated
// the pointer-decrement side effect without the actual placement (there
// was no real sort consuming sa[0:m] yet in that milestone). Iterates
// i = m-2 downto 0, then i = m-1 last, exactly matching the C source's
// order (relevant because BUCKET_BSTAR's slots are consumed in that
// sequence).
func dsBucketBStarSuffixes(text []byte, sa []int32, pab []int32, bucketB []int32, m int) {
	for i := m - 2; i >= 0; i-- {
		t := pab[i]
		c0 := int(text[t])
		c1 := int(text[t+1])
		bucketB[bucketBStarIndex(c0, c1)]--
		sa[bucketB[bucketBStarIndex(c0, c1)]] = int32(i)
	}
	t := pab[m-1]
	c0 := int(text[t])
	c1 := int(text[t+1])
	bucketB[bucketBStarIndex(c0, c1)]--
	sa[bucketB[bucketBStarIndex(c0, c1)]] = int32(m - 1)
}

// dsComputeBStarRanks is a faithful, line-by-line translation of
// divsufsort.c's "Compute ranks of type B* substrings" (lines 151-162),
// run after dsSssort has sorted sa[0:m] (compact B*-indices) as far as
// bounded-depth comparison allows. Individually-resolved entries
// (non-negative sa[i], meaning sssort/ss_partition confirmed they're
// distinct from their neighbor) get a unique dense rank equal to their
// array position, and the C source's SA[i+1]=i-j skip-marker encoding is
// written at the boundary just past each resolved run -- trsort's own
// main loop parses that encoding directly out of sa[0:m] to skip already-
// resolved stretches, so it must be reproduced exactly here, unlike
// Milestone 2's version of this function (which didn't call trsort and
// so didn't need it). Runs of ^-marked (negative) entries are tied groups
// sssort could not fully order; they provisionally share one rank here
// (matching the C source exactly) -- dsTrsort resolves them for real.
func dsComputeBStarRanks(sa []int32, isab []int32, m int) {
	for i := m - 1; i >= 0; i-- {
		if sa[i] >= 0 {
			j := i
			for {
				isab[sa[i]] = int32(i)
				i--
				if !(i >= 0 && sa[i] >= 0) {
					break
				}
			}
			sa[i+1] = int32(i - j)
			if i <= 0 {
				break
			}
		}
		j := i
		for {
			sa[i] = ^sa[i]
			isab[sa[i]] = int32(j)
			i--
			if !(sa[i] < 0) {
				break
			}
		}
		isab[sa[i]] = int32(j)
	}
}

// dsPlaceBStarSuffixes is a close translation of divsufsort.c's "Set the
// sorted order of type B* suffixes" (lines ~168-175) followed by "Calculate
// the index of start/end point of each bucket" + "Move all type B*
// suffixes to the correct position" (lines ~177-192). Re-scans text with
// the same classification pattern as dsClassifyAndCount (necessarily
// visiting B* positions in the same order, since both are the same
// deterministic scan over the same immutable text), using isab to place
// each B*-suffix's text position at its correct rank-ordered slot, marking
// entries with divsufsort's `^s` ("not yet typed by induction") convention,
// then recomputes bucketB's B-view end pointers from bucketA and moves the
// now rank-placed B* positions into their final bucket slots within sa.
//
// Preserves the C source's `^x` (Go) / `~x` (C) sign-bit marker idiom
// deliberately as-is: Go's unary ^ on a signed integer is bit-for-bit -x-1
// under Go's mandated two's-complement semantics, a direct drop-in for C's
// ~x here -- not "cleaned up" into something more defensive, since that
// would change behavior construct_SA depends on.
func dsPlaceBStarSuffixes(text []byte, sa []int32, isab []int32, bucketA, bucketB []int32, m int) {
	n := len(text)

	// "Set the sorted order of type B* suffixes."
	i := n - 1
	j := m
	c0 := int(text[n-1])
	for i >= 0 {
		i--
		c1 := c0
		for i >= 0 {
			c0 = int(text[i])
			if c0 < c1 {
				break
			}
			c1 = c0
			i--
		}
		if i < 0 {
			break
		}
		t := i
		i--
		c1 = c0
		for i >= 0 {
			c0 = int(text[i])
			if c0 > c1 {
				break
			}
			c1 = c0
			i--
		}
		j--
		slot := isab[j]
		if t == 0 || (t-i) > 1 {
			sa[slot] = int32(t)
		} else {
			sa[slot] = ^int32(t)
		}
	}

	// "Calculate the index of start/end point of each bucket" +
	// "Move all type B* suffixes to the correct position."
	bucketB[bucketBIndex(255, 255)] = int32(n)
	k := m - 1
	for c0 := 254; c0 >= 0; c0-- {
		ii := int(bucketA[c0+1]) - 1
		for c1 := 255; c1 > c0; c1-- {
			t := ii - int(bucketB[bucketBIndex(c0, c1)])
			bucketB[bucketBIndex(c0, c1)] = int32(ii)

			jj := int(bucketB[bucketBStarIndex(c0, c1)])
			for jj <= k {
				sa[t] = sa[k]
				t--
				k--
			}
			ii = t
		}
		bucketB[bucketBStarIndex(c0, c0+1)] = int32(ii - int(bucketB[bucketBIndex(c0, c0)]) + 1)
		bucketB[bucketBIndex(c0, c0)] = int32(ii)
	}
}

// dsInduceSuffixArray is a close translation of divsufsort.c's
// construct_SA, lines ~198-260: induces every non-B*-suffix position from
// the now correctly placed and sorted B* suffixes, in two passes -- type B
// suffixes via a right-to-left scan per bucket, then type A (and any
// remainder) via a single left-to-right scan over the whole array. Uses
// the same `^x` marker convention as dsPlaceBStarSuffixes, for the same
// reason.
func dsInduceSuffixArray(text []byte, sa []int32, bucketA, bucketB []int32, m int) {
	n := len(text)

	if m > 0 {
		for c1 := 254; c1 >= 0; c1-- {
			lo := int(bucketB[bucketBStarIndex(c1, c1+1)])
			hi := int(bucketA[c1+1]) - 1
			var k int
			c2 := -1
			for jPos := hi; jPos >= lo; jPos-- {
				s := int(sa[jPos])
				if s > 0 {
					sa[jPos] = ^int32(s)
					s--
					c0 := int(text[s])
					if s > 0 && int(text[s-1]) > c0 {
						s = ^s
					}
					if c0 != c2 {
						if c2 >= 0 {
							bucketB[bucketBIndex(c2, c1)] = int32(k)
						}
						c2 = c0
						k = int(bucketB[bucketBIndex(c2, c1)])
					}
					sa[k] = int32(s)
					k--
				} else {
					sa[jPos] = ^int32(s)
				}
			}
		}
	}

	c2 := int(text[n-1])
	k := int(bucketA[c2])
	if int(text[n-2]) < c2 {
		sa[k] = ^int32(n - 1)
	} else {
		sa[k] = int32(n - 1)
	}
	k++

	for iPos := 0; iPos < n; iPos++ {
		s := int(sa[iPos])
		if s > 0 {
			s--
			c0 := int(text[s])
			if s == 0 || int(text[s-1]) < c0 {
				s = ^s
			}
			if c0 != c2 {
				bucketA[c2] = int32(k)
				c2 = c0
				k = int(bucketA[c2])
			}
			sa[k] = int32(s)
			k++
		} else {
			sa[iPos] = ^int32(s)
		}
	}
}

// computeSuffixArrayDivSufSort computes the suffix array of text into sa
// (must satisfy len(sa) == len(text)), using divsufsort's overall algorithm
// shape. See the file header for exactly what is and isn't ported this
// milestone. Not wired into any production code path.
//
// Allocates its own bucketA/bucketB scratch (256 and 256*256 int32 slots);
// see computeSuffixArrayDivSufSort0Alloc for the pool-friendly variant with
// no allocation, used for apples-to-apples benchmarking against production's
// 0-alloc sais_8_32 path.
func computeSuffixArrayDivSufSort(text []byte, sa []int32) {
	var bucketA [256]int32
	var bucketB [256 * 256]int32
	computeSuffixArrayDivSufSortWithBuckets(text, sa, bucketA[:], bucketB[:])
}

// computeSuffixArrayDivSufSort0Alloc is computeSuffixArrayDivSufSort with
// caller-supplied bucketA (len 256) / bucketB (len 256*256) scratch, so a
// pool-reused caller (mirroring ScratchData's pattern in sa_fast.go) never
// allocates them fresh per call. Stage 3's original version declared these
// as local vars inside computeSuffixArrayDivSufSort; escape analysis
// heap-allocated bucketB (262144 B/op, the port's one remaining alloc/op),
// since a pointer into it is threaded through every helper call.
//
// Unlike sa (see TestSuffixArrayDivSufSortUnzeroedBufferReuse -- proven, not
// assumed, to need no zeroing), bucketA/bucketB genuinely do need to start
// zeroed every call: dsClassifyAndCount accumulates counts into them via
// `bucketA[c1]++`/`bucketB[...]++`, so residue from a pool-reused buffer's
// prior call directly corrupts the next call's bucket offsets. Caught this
// empirically, not by inspection: reusing bucketA/bucketB across benchmark
// iterations without clearing them produced a real out-of-bounds panic in
// dsBucketBStarSuffixes on the very first run. So, unlike sa, this wrapper
// clears them itself rather than leaving it to the caller.
func computeSuffixArrayDivSufSort0Alloc(text []byte, sa []int32, bucketA []int32, bucketB []int32) {
	if len(bucketA) != 256 || len(bucketB) != 256*256 {
		panic("computeSuffixArrayDivSufSort0Alloc: bucketA/bucketB wrong size")
	}
	for i := range bucketA {
		bucketA[i] = 0
	}
	for i := range bucketB {
		bucketB[i] = 0
	}
	computeSuffixArrayDivSufSortWithBuckets(text, sa, bucketA, bucketB)
}

func computeSuffixArrayDivSufSortWithBuckets(text []byte, sa []int32, bucketA []int32, bucketB []int32) {
	n := len(text)
	if len(sa) != n {
		panic("computeSuffixArrayDivSufSort: len(sa) != len(text)")
	}
	if n == 0 {
		return
	}
	if n == 1 {
		sa[0] = 0
		return
	}
	if n == 2 {
		// Mirrors divsufsort.c's divsufsort() public wrapper, which
		// special-cases n<=2 explicitly rather than running the general
		// algorithm on them: m = (T[0] < T[1]); SA[m^1] = 0, SA[m] = 1.
		m := int32(0)
		if text[0] < text[1] {
			m = 1
		}
		sa[m^1] = 0
		sa[m] = 1
		return
	}

	m := dsClassifyAndCount(text, sa, bucketA[:], bucketB[:])
	dsComputeBucketOffsets(bucketA[:], bucketB[:])

	if m > 0 {
		pab := sa[n-m:]
		// isab spans sa[m:n] (not sa[m:m+m]) to match real divsufsort's
		// ISAb = SA+m, which extends all the way to SA+n: trsort's rank-
		// doubling genuinely uses that region beyond the first m slots as
		// scratch (tr_copy/tr_partialcopy write there), it is not
		// incidental slack. dsPlaceBStarSuffixes below only ever indexes
		// isab[j] for j in [0,m), so the wider slice is fully backward
		// compatible with it.
		isab := sa[m:n]
		dsBucketBStarSuffixes(text, sa, pab, bucketB[:], m)

		// Sort the type B* substrings using sssort, mirroring
		// divsufsort.c's non-OpenMP loop (lines ~140-148) exactly,
		// including the carried-forward j between c0 iterations.
		buf := m
		bufsize := n - 2*m
		j := m
		for c0 := 254; j > 0; c0-- {
			for c1 := 255; c0 < c1; {
				i := int(bucketB[bucketBStarIndex(c0, c1)])
				if j-i > 1 {
					lastsuffix := sa[i] == int32(m-1)
					dsSssort(text, pab, sa, i, j, buf, bufsize, 2, n, lastsuffix)
				}
				j = i
				c1--
			}
		}

		// pab (sa[n-m:]) and isab (sa[m:n]) alias the same backing array
		// and generally overlap, but trsort never reads PAb again once
		// rank computation begins (it operates purely on sa[0:m] and
		// isab), so unlike Milestone 2's tie-break fallback, nothing here
		// needs a pre-mutation snapshot of pab.
		dsComputeBStarRanks(sa, isab, m)
		dsTrsort(isab, sa, m, 1)

		dsPlaceBStarSuffixes(text, sa, isab, bucketA[:], bucketB[:], m)
	}

	dsInduceSuffixArray(text, sa, bucketA[:], bucketB[:], m)
}
