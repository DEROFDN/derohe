package astrobwtv3

// Stage 3, Milestone 2 of the staged Go port of libdivsufsort (see
// divsufsort_go.go's file header for the overall project framing). This
// file is a close, function-by-function translation of sssort.c (Yuta
// Mori, MIT license; unmodified reference at
// assets/tnn-miner/src/crypto/astrobwtv3/sssort.c) -- the bounded-depth
// multikey-quicksort + block-merge machinery that sorts type B* suffixes
// substring-by-substring, replacing Milestone 1's placeholder
// full-comparison sort for the (large majority of) B*-suffixes it can
// fully resolve.
//
// Translation conventions (established in divsufsort_go.go, reused here):
//   - every C pointer into the shared SA array becomes a plain Go int
//     index into one shared sa []int32 slice -- never a relocated Go
//     sub-slice, because the caller genuinely aliases regions of this same
//     backing array (e.g. sssort's "buf" parameter is a window into sa
//     itself), and cross-region pointer comparisons are far safer to get
//     right in one consistent index space.
//   - PA (this codebase's pab []int32) stays a genuine read-only slice,
//     indexed by compact B*-index.
//   - ^x (Go) for C's ~x, exactly as established.
//   - assert() -> comments documenting the invariant, not runtime checks.
//
// This build's active config (assets/tnn-miner/.../divsufsort_private.h):
// SS_BLOCKSIZE=1024, SS_INSERTIONSORT_THRESHOLD=8, SS_MISORT_STACKSIZE=16
// (SS_BLOCKSIZE<=4096), SS_SMERGE_STACKSIZE=32 (32-bit saidx_t build).
// m (B*-suffix count) is ~22,000 for real ~66-71KB AstroBWTv3 inputs, well
// above SS_BLOCKSIZE, so the block-merge path is not a cold path here --
// it is exercised on every hash, which is why this milestone ports it in
// full rather than the simpler SS_BLOCKSIZE==0 variant.
//
// Known, deliberate gap: ss_compare's comparison depth is bounded by the
// *next* B*-suffix's text position (it sorts substrings, not full
// suffixes), so sssort alone cannot resolve every tie -- real divsufsort
// uses trsort's Larsson-Sadakane doubling for that (Stage 3 Milestone 3,
// not yet ported). divsufsort_go.go's caller falls back to a full
// suffix-comparison tie-break for any run sssort leaves undetermined.

const (
	dsSsInsertionsortThreshold = 8    // SS_INSERTIONSORT_THRESHOLD
	dsSSBlocksize              = 1024 // SS_BLOCKSIZE
	dsSsMisortStackSize        = 16   // SS_MISORT_STACKSIZE (SS_BLOCKSIZE<=4096)
	dsSsSmergeStackSize        = 32   // SS_SMERGE_STACKSIZE (32-bit build)
)

// lg_table / sqq_table: direct copies of sssort.c's static lookup tables.
var dsSsLgTable = [256]int8{
	-1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
}

var dsSsSqqTable = [256]int16{
	0, 16, 22, 27, 32, 35, 39, 42, 45, 48, 50, 53, 55, 57, 59, 61,
	64, 65, 67, 69, 71, 73, 75, 76, 78, 80, 81, 83, 84, 86, 87, 89,
	90, 91, 93, 94, 96, 97, 98, 99, 101, 102, 103, 104, 106, 107, 108, 109,
	110, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126,
	128, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
	143, 144, 144, 145, 146, 147, 148, 149, 150, 150, 151, 152, 153, 154, 155, 155,
	156, 157, 158, 159, 160, 160, 161, 162, 163, 163, 164, 165, 166, 167, 167, 168,
	169, 170, 170, 171, 172, 173, 173, 174, 175, 176, 176, 177, 178, 178, 179, 180,
	181, 181, 182, 183, 183, 184, 185, 185, 186, 187, 187, 188, 189, 189, 190, 191,
	192, 192, 193, 193, 194, 195, 195, 196, 197, 197, 198, 199, 199, 200, 201, 201,
	202, 203, 203, 204, 204, 205, 206, 206, 207, 208, 208, 209, 209, 210, 211, 211,
	212, 212, 213, 214, 214, 215, 215, 216, 217, 217, 218, 218, 219, 219, 220, 221,
	221, 222, 222, 223, 224, 224, 225, 225, 226, 226, 227, 227, 228, 229, 229, 230,
	230, 231, 231, 232, 232, 233, 234, 234, 235, 235, 236, 236, 237, 237, 238, 238,
	239, 240, 240, 241, 241, 242, 242, 243, 243, 244, 244, 245, 245, 246, 246, 247,
	247, 248, 248, 249, 249, 250, 250, 251, 251, 252, 252, 253, 253, 254, 254, 255,
}

// dsSsIlg mirrors ss_ilg for the active SS_BLOCKSIZE=1024 config (the
// "#else" branch of the C source's #if ladder -- SS_BLOCKSIZE is neither
// 0 nor <256).
func dsSsIlg(n int) int {
	if n&0xff00 != 0 {
		return 8 + int(dsSsLgTable[(n>>8)&0xff])
	}
	return int(dsSsLgTable[n&0xff])
}

// dsSsIsqrt mirrors ss_isqrt exactly.
func dsSsIsqrt(x int) int {
	if x >= dsSSBlocksize*dsSSBlocksize {
		return dsSSBlocksize
	}
	var e int
	if x&0xffff0000 != 0 {
		if x&0xff000000 != 0 {
			e = 24 + int(dsSsLgTable[(x>>24)&0xff])
		} else {
			e = 16 + int(dsSsLgTable[(x>>16)&0xff])
		}
	} else {
		if x&0x0000ff00 != 0 {
			e = 8 + int(dsSsLgTable[(x>>8)&0xff])
		} else {
			e = int(dsSsLgTable[x&0xff])
		}
	}
	var y int
	if e >= 16 {
		y = int(dsSsSqqTable[x>>((e-6)-(e&1))]) << (uint(e>>1) - 7)
		if e >= 24 {
			y = (y + 1 + x/y) >> 1
		}
		y = (y + 1 + x/y) >> 1
	} else if e >= 8 {
		y = (int(dsSsSqqTable[x>>((e-6)-(e&1))]) >> (7 - (e >> 1))) + 1
	} else {
		return int(dsSsSqqTable[x]) >> 4
	}
	if x < y*y {
		return y - 1
	}
	return y
}

// dsSsCompare mirrors ss_compare: compares two B*-substrings starting at
// depth, bounded by each substring's "next boundary" position (p1next/
// p2next -- the next B*-suffix's text position in PAb array order, or a
// synthetic sentinel for the special last-suffix case in dsSssort).
// Callers pass p1pos/p1next as pab[idx]/pab[idx+1] at the normal (PAb-
// indexed) call sites, or a synthetic (position, n-2) pair for the one
// special case -- kept as explicit values rather than an index into pab
// so both shapes are handled uniformly without an artificial second array.
func dsSsCompare(text []byte, depth int, p1pos, p1next, p2pos, p2next int) int {
	u1 := depth + p1pos
	u2 := depth + p2pos
	u1n := p1next + 2
	u2n := p2next + 2
	for u1 < u1n && u2 < u2n && text[u1] == text[u2] {
		u1++
		u2++
	}
	if u1 < u1n {
		if u2 < u2n {
			return int(text[u1]) - int(text[u2])
		}
		return 1
	}
	if u2 < u2n {
		return -1
	}
	return 0
}

// dsSsComparePAB is dsSsCompare specialized for the common case where both
// operands are compact B*-indices into pab (the overwhelming majority of
// call sites: PA + x in the C source).
func dsSsComparePAB(text []byte, pab []int32, depth int, p1, p2 int) int {
	return dsSsCompare(text, depth, int(pab[p1]), int(pab[p1+1]), int(pab[p2]), int(pab[p2+1]))
}

// dsSsInsertionsort mirrors ss_insertionsort: insertion sort for small
// (<=SS_INSERTIONSORT_THRESHOLD) groups. sa[first:last] holds compact
// B*-indices.
func dsSsInsertionsort(text []byte, pab []int32, sa []int32, first, last, depth int) {
	for i := last - 2; first <= i; i-- {
		t := sa[i]
		j := i + 1
		r := dsSsComparePAB(text, pab, depth, int(t), int(sa[j]))
		for r > 0 {
			for {
				sa[j-1] = sa[j]
				j++
				if !(j < last && sa[j] < 0) {
					break
				}
			}
			if last <= j {
				break
			}
			r = dsSsComparePAB(text, pab, depth, int(t), int(sa[j]))
		}
		if r == 0 {
			sa[j] = ^sa[j]
		}
		sa[j-1] = t
	}
}

// dsSsFixdown mirrors ss_fixdown: sift-down step for the heapsort fallback.
// sa[base:base+size] is the heap; i is relative to base.
func dsSsFixdown(text []byte, depth int, pab []int32, sa []int32, base, i, size int) {
	v := sa[base+i]
	c := int(text[depth+int(pab[v])])
	for {
		j := 2*i + 1
		if j >= size {
			break
		}
		k := j
		j++
		d := int(text[depth+int(pab[sa[base+k]])])
		if j < size {
			if e := int(text[depth+int(pab[sa[base+j]])]); d < e {
				k = j
				d = e
			}
		}
		if d <= c {
			break
		}
		sa[base+i] = sa[base+k]
		i = k
	}
	sa[base+i] = v
}

// dsSsHeapsort mirrors ss_heapsort exactly.
func dsSsHeapsort(text []byte, depth int, pab []int32, sa []int32, base, size int) {
	m := size
	if size%2 == 0 {
		m--
		if text[depth+int(pab[sa[base+m/2]])] < text[depth+int(pab[sa[base+m]])] {
			sa[base+m], sa[base+m/2] = sa[base+m/2], sa[base+m]
		}
	}
	for i := m/2 - 1; i >= 0; i-- {
		dsSsFixdown(text, depth, pab, sa, base, i, m)
	}
	if size%2 == 0 {
		sa[base+0], sa[base+m] = sa[base+m], sa[base+0]
		dsSsFixdown(text, depth, pab, sa, base, 0, m)
	}
	for i := m - 1; i > 0; i-- {
		t := sa[base+0]
		sa[base+0] = sa[base+i]
		dsSsFixdown(text, depth, pab, sa, base, 0, i)
		sa[base+i] = t
	}
}

// dsSsMedian3 mirrors ss_median3. v1/v2/v3 are sa-indices; SWAP here
// exchanges which index is being referred to (the C source swaps the
// pointer variables themselves, not the array values they point at).
func dsSsMedian3(text []byte, depth int, pab []int32, sa []int32, v1, v2, v3 int) int {
	val := func(v int) byte { return text[depth+int(pab[sa[v]])] }
	if val(v1) > val(v2) {
		v1, v2 = v2, v1
	}
	if val(v2) > val(v3) {
		if val(v1) > val(v3) {
			return v1
		}
		return v3
	}
	return v2
}

// dsSsMedian5 mirrors ss_median5, same index-swap convention as dsSsMedian3.
func dsSsMedian5(text []byte, depth int, pab []int32, sa []int32, v1, v2, v3, v4, v5 int) int {
	val := func(v int) byte { return text[depth+int(pab[sa[v]])] }
	if val(v2) > val(v3) {
		v2, v3 = v3, v2
	}
	if val(v4) > val(v5) {
		v4, v5 = v5, v4
	}
	if val(v2) > val(v4) {
		v2, v4 = v4, v2
		v3, v5 = v5, v3
	}
	if val(v1) > val(v3) {
		v1, v3 = v3, v1
	}
	if val(v1) > val(v4) {
		v1, v4 = v4, v1
		v3, v5 = v5, v3
	}
	if val(v3) > val(v4) {
		return v4
	}
	return v3
}

// dsSsPivot mirrors ss_pivot: chooses a pivot index via median-of-3 or
// median-of-5 (or a 3-level median-of-medians for large ranges).
func dsSsPivot(text []byte, depth int, pab []int32, sa []int32, first, last int) int {
	t := last - first
	middle := first + t/2
	if t <= 512 {
		if t <= 32 {
			return dsSsMedian3(text, depth, pab, sa, first, middle, last-1)
		}
		t >>= 2
		return dsSsMedian5(text, depth, pab, sa, first, first+t, middle, last-1-t, last-1)
	}
	t >>= 3
	first = dsSsMedian3(text, depth, pab, sa, first, first+t, first+(t<<1))
	middle = dsSsMedian3(text, depth, pab, sa, middle-t, middle, middle+t)
	last = dsSsMedian3(text, depth, pab, sa, last-1-(t<<1), last-1-t, last-1)
	return dsSsMedian3(text, depth, pab, sa, first, middle, last)
}

// dsSsPartition mirrors ss_partition: binary partition for substrings,
// marking already-correctly-placed entries with the ^x sentinel.
func dsSsPartition(pab []int32, sa []int32, first, last, depth int) int {
	a := first - 1
	b := last
	for {
		for {
			a++
			if !(a < b) {
				break
			}
			if !(int(pab[sa[a]])+depth >= int(pab[sa[a]+1])+1) {
				break
			}
			sa[a] = ^sa[a]
		}
		for {
			b--
			if !(a < b) {
				break
			}
			if !(int(pab[sa[b]])+depth < int(pab[sa[b]+1])+1) {
				break
			}
		}
		if b <= a {
			break
		}
		t := ^sa[b]
		sa[b] = sa[a]
		sa[a] = t
	}
	if first < a {
		sa[first] = ^sa[first]
	}
	return a
}

// dsSsStackEntry mirrors ss_mintrosort's/ss_swapmerge's local stack{} tuple.
type dsSsStackEntry struct {
	a, b, c, d int
}

// dsSsMintrosort mirrors ss_mintrosort: multikey introsort (quicksort by
// increasing comparison depth, falling back to heapsort past a recursion-
// depth budget) for medium-sized B*-substring groups. sa[first:last] holds
// compact B*-indices.
func dsSsMintrosort(text []byte, pab []int32, sa []int32, first, last, depth int) {
	var stack [dsSsMisortStackSize]dsSsStackEntry
	ssize := 0
	push := func(a, b, c, d int) {
		stack[ssize] = dsSsStackEntry{a, b, c, d}
		ssize++
	}
	td := func(idx int) int { return int(text[depth+int(pab[sa[idx]])]) }

	limit := dsSsIlg(last - first)
	var v, x int

	for {
		if last-first <= dsSsInsertionsortThreshold {
			if last-first > 1 {
				dsSsInsertionsort(text, pab, sa, first, last, depth)
			}
			if ssize == 0 {
				return
			}
			ssize--
			e := stack[ssize]
			first, last, depth, limit = e.a, e.b, e.c, e.d
			continue
		}

		oldLimit := limit
		limit--
		if oldLimit == 0 {
			dsSsHeapsort(text, depth, pab, sa, first, last-first)
		}
		if limit < 0 {
			a := first + 1
			v = td(first)
			for ; a < last; a++ {
				x = td(a)
				if x != v {
					if a-first > 1 {
						break
					}
					v = x
					first = a
				}
			}
			if int(text[depth+int(pab[sa[first]])-1]) < v {
				first = dsSsPartition(pab, sa, first, a, depth)
			}
			if a-first <= last-a {
				if a-first > 1 {
					push(a, last, depth, -1)
					last = a
					depth++
					limit = dsSsIlg(a - first)
				} else {
					first = a
					limit = -1
				}
			} else {
				if last-a > 1 {
					push(first, a, depth+1, dsSsIlg(a-first))
					first = a
					limit = -1
				} else {
					last = a
					depth++
					limit = dsSsIlg(a - first)
				}
			}
			continue
		}

		// choose pivot
		a := dsSsPivot(text, depth, pab, sa, first, last)
		v = td(a)
		sa[first], sa[a] = sa[a], sa[first]

		// partition
		b := first
		for {
			b++
			if b >= last {
				break
			}
			x = td(b)
			if x != v {
				break
			}
		}
		a = b
		if a < last && x < v {
			for {
				b++
				if b >= last {
					break
				}
				x = td(b)
				if x > v {
					break
				}
				if x == v {
					sa[b], sa[a] = sa[a], sa[b]
					a++
				}
			}
		}
		c := last
		for {
			c--
			if b >= c {
				break
			}
			x = td(c)
			if x != v {
				break
			}
		}
		d := c
		if b < d && x > v {
			for {
				c--
				if b >= c {
					break
				}
				x = td(c)
				if x < v {
					break
				}
				if x == v {
					sa[c], sa[d] = sa[d], sa[c]
					d--
				}
			}
		}
		for b < c {
			sa[b], sa[c] = sa[c], sa[b]
			for {
				b++
				if b >= c {
					break
				}
				x = td(b)
				if x > v {
					break
				}
				if x == v {
					sa[b], sa[a] = sa[a], sa[b]
					a++
				}
			}
			for {
				c--
				if b >= c {
					break
				}
				x = td(c)
				if x < v {
					break
				}
				if x == v {
					sa[c], sa[d] = sa[d], sa[c]
					d--
				}
			}
		}

		if a <= d {
			c = b - 1
			s := a - first
			t := b - a
			if s > t {
				s = t
			}
			e, f := first, b-s
			for ; s > 0; s, e, f = s-1, e+1, f+1 {
				sa[e], sa[f] = sa[f], sa[e]
			}
			s = d - c
			t = last - d - 1
			if s > t {
				s = t
			}
			e, f = b, last-s
			for ; s > 0; s, e, f = s-1, e+1, f+1 {
				sa[e], sa[f] = sa[f], sa[e]
			}

			a = first + (b - a)
			c = last - (d - c)
			if v <= int(text[depth+int(pab[sa[a]])-1]) {
				b = a
			} else {
				b = dsSsPartition(pab, sa, a, c, depth)
			}

			if a-first <= last-c {
				if last-c <= c-b {
					push(b, c, depth+1, dsSsIlg(c-b))
					push(c, last, depth, limit)
					last = a
				} else if a-first <= c-b {
					push(c, last, depth, limit)
					push(b, c, depth+1, dsSsIlg(c-b))
					last = a
				} else {
					push(c, last, depth, limit)
					push(first, a, depth, limit)
					first, last, depth, limit = b, c, depth+1, dsSsIlg(c-b)
				}
			} else {
				if a-first <= c-b {
					push(b, c, depth+1, dsSsIlg(c-b))
					push(first, a, depth, limit)
					first = c
				} else if last-c <= c-b {
					push(first, a, depth, limit)
					push(b, c, depth+1, dsSsIlg(c-b))
					first = c
				} else {
					push(first, a, depth, limit)
					push(c, last, depth, limit)
					first, last, depth, limit = b, c, depth+1, dsSsIlg(c-b)
				}
			}
		} else {
			limit++
			if int(text[depth+int(pab[sa[first]])-1]) < v {
				first = dsSsPartition(pab, sa, first, last, depth)
				limit = dsSsIlg(last - first)
			}
			depth++
		}
	}
}

// dsSsBlockswap mirrors ss_blockswap: swaps two equal-length ranges.
func dsSsBlockswap(sa []int32, a, b, n int) {
	for ; n > 0; n-- {
		sa[a], sa[b] = sa[b], sa[a]
		a++
		b++
	}
}

// dsSsRotate mirrors ss_rotate: in-place block rotation via cyclic shifts.
func dsSsRotate(sa []int32, first, middle, last int) {
	l := middle - first
	r := last - middle
	for l > 0 && r > 0 {
		if l == r {
			dsSsBlockswap(sa, first, middle, l)
			break
		}
		if l < r {
			a := last - 1
			b := middle - 1
			t := sa[a]
			for {
				sa[a] = sa[b]
				a--
				sa[b] = sa[a]
				b--
				if b < first {
					sa[a] = t
					last = a
					r -= l + 1
					if r <= l {
						break
					}
					a--
					b = middle - 1
					t = sa[a]
				}
			}
		} else {
			a := first
			b := middle
			t := sa[a]
			for {
				sa[a] = sa[b]
				a++
				sa[b] = sa[a]
				b++
				if last <= b {
					sa[a] = t
					first = a + 1
					l -= r + 1
					if l <= r {
						break
					}
					a++
					b = middle
					t = sa[a]
				}
			}
		}
	}
}

// dsGetIdx mirrors the GETIDX macro: resolves a possibly ^-marked sa entry
// back to its true (non-negative) compact index.
func dsGetIdx(v int32) int {
	if v >= 0 {
		return int(v)
	}
	return int(^v)
}

// dsSsInplacemerge mirrors ss_inplacemerge: binary-search-driven in-place
// merge used as the final cleanup step when a leftover unbuffered tail
// remains (sssort's "limit != 0" case).
func dsSsInplacemerge(text []byte, pab []int32, sa []int32, first, middle, last, depth int) {
	for {
		var x, p int
		if sa[last-1] < 0 {
			x = 1
			p = int(^sa[last-1])
		} else {
			x = 0
			p = int(sa[last-1])
		}
		a := first
		length := middle - first
		half := length >> 1
		r := -1
		for length > 0 {
			b := a + half
			q := dsSsComparePAB(text, pab, depth, dsGetIdx(sa[b]), p)
			if q < 0 {
				a = b + 1
				half -= (length & 1) ^ 1
			} else {
				r = q
			}
			length = half
			half >>= 1
		}
		if a < middle {
			if r == 0 {
				sa[a] = ^sa[a]
			}
			dsSsRotate(sa, a, middle, last)
			last -= middle - a
			middle = a
			if first == middle {
				break
			}
		}
		last--
		if x != 0 {
			for {
				last--
				if !(sa[last] < 0) {
					break
				}
			}
		}
		if middle == last {
			break
		}
	}
}

// dsSsMergeforward mirrors ss_mergeforward: merges [first,middle) and
// [middle,last) forward using an auxiliary buffer of size >= middle-first.
func dsSsMergeforward(text []byte, pab []int32, sa []int32, first, middle, last, buf, depth int) {
	bufend := buf + (middle - first) - 1
	dsSsBlockswap(sa, buf, first, middle-first)

	a := first
	t := sa[a]
	b := buf
	c := middle
	for {
		r := dsSsComparePAB(text, pab, depth, int(sa[b]), int(sa[c]))
		if r < 0 {
			for {
				sa[a] = sa[b]
				a++
				if bufend <= b {
					sa[bufend] = t
					return
				}
				sa[b] = sa[a]
				b++
				if sa[b] >= 0 {
					break
				}
			}
		} else if r > 0 {
			for {
				sa[a] = sa[c]
				a++
				sa[c] = sa[a]
				c++
				if last <= c {
					for b < bufend {
						sa[a] = sa[b]
						a++
						sa[b] = sa[a]
						b++
					}
					sa[a] = sa[b]
					sa[b] = t
					return
				}
				if sa[c] >= 0 {
					break
				}
			}
		} else {
			sa[c] = ^sa[c]
			for {
				sa[a] = sa[b]
				a++
				if bufend <= b {
					sa[bufend] = t
					return
				}
				sa[b] = sa[a]
				b++
				if sa[b] >= 0 {
					break
				}
			}
			for {
				sa[a] = sa[c]
				a++
				sa[c] = sa[a]
				c++
				if last <= c {
					for b < bufend {
						sa[a] = sa[b]
						a++
						sa[b] = sa[a]
						b++
					}
					sa[a] = sa[b]
					sa[b] = t
					return
				}
				if sa[c] >= 0 {
					break
				}
			}
		}
	}
}

// dsSsMergebackward mirrors ss_mergebackward: same as dsSsMergeforward but
// merging from the high end downward, tracking via the x bitmask whether
// p1/p2 currently reference an already-^-resolved position.
func dsSsMergebackward(text []byte, pab []int32, sa []int32, first, middle, last, buf, depth int) {
	bufend := buf + (last - middle) - 1
	dsSsBlockswap(sa, buf, middle, last-middle)

	x := 0
	var p1, p2 int
	if sa[bufend] < 0 {
		p1 = int(^sa[bufend])
		x |= 1
	} else {
		p1 = int(sa[bufend])
	}
	if sa[middle-1] < 0 {
		p2 = int(^sa[middle-1])
		x |= 2
	} else {
		p2 = int(sa[middle-1])
	}

	a := last - 1
	t := sa[a]
	b := bufend
	c := middle - 1
	for {
		r := dsSsComparePAB(text, pab, depth, p1, p2)
		if r > 0 {
			if x&1 != 0 {
				for {
					sa[a] = sa[b]
					a--
					sa[b] = sa[a]
					b--
					if sa[b] >= 0 {
						break
					}
				}
				x ^= 1
			}
			sa[a] = sa[b]
			a--
			if b <= buf {
				sa[buf] = t
				break
			}
			sa[b] = sa[a]
			b--
			if sa[b] < 0 {
				p1 = int(^sa[b])
				x |= 1
			} else {
				p1 = int(sa[b])
			}
		} else if r < 0 {
			if x&2 != 0 {
				for {
					sa[a] = sa[c]
					a--
					sa[c] = sa[a]
					c--
					if sa[c] >= 0 {
						break
					}
				}
				x ^= 2
			}
			sa[a] = sa[c]
			a--
			sa[c] = sa[a]
			c--
			if c < first {
				for buf < b {
					sa[a] = sa[b]
					a--
					sa[b] = sa[a]
					b--
				}
				sa[a] = sa[b]
				sa[b] = t
				break
			}
			if sa[c] < 0 {
				p2 = int(^sa[c])
				x |= 2
			} else {
				p2 = int(sa[c])
			}
		} else {
			if x&1 != 0 {
				for {
					sa[a] = sa[b]
					a--
					sa[b] = sa[a]
					b--
					if sa[b] >= 0 {
						break
					}
				}
				x ^= 1
			}
			sa[a] = ^sa[b]
			a--
			if b <= buf {
				sa[buf] = t
				break
			}
			sa[b] = sa[a]
			b--
			if x&2 != 0 {
				for {
					sa[a] = sa[c]
					a--
					sa[c] = sa[a]
					c--
					if sa[c] >= 0 {
						break
					}
				}
				x ^= 2
			}
			sa[a] = sa[c]
			a--
			sa[c] = sa[a]
			c--
			if c < first {
				for buf < b {
					sa[a] = sa[b]
					a--
					sa[b] = sa[a]
					b--
				}
				sa[a] = sa[b]
				sa[b] = t
				break
			}
			if sa[b] < 0 {
				p1 = int(^sa[b])
				x |= 1
			} else {
				p1 = int(sa[b])
			}
			if sa[c] < 0 {
				p2 = int(^sa[c])
				x |= 2
			} else {
				p2 = int(sa[c])
			}
		}
	}
}

// dsSsMergeCheck mirrors the MERGE_CHECK macro embedded in ss_swapmerge:
// conditionally marks sa[a]/sa[b] with the ^ sentinel based on the check
// bitmask and adjacent-entry comparisons. At every call site in this file
// a and b are literally (first, last), matching the C macro's only usage
// pattern -- written as a real function rather than force-generalized.
func dsSsMergeCheck(text []byte, pab []int32, sa []int32, depth, a, b, check int) {
	if check&1 != 0 || (check&2 != 0 && dsSsComparePAB(text, pab, depth, dsGetIdx(sa[a-1]), int(sa[a])) == 0) {
		sa[a] = ^sa[a]
	}
	if check&4 != 0 && dsSsComparePAB(text, pab, depth, dsGetIdx(sa[b-1]), int(sa[b])) == 0 {
		sa[b] = ^sa[b]
	}
}

// dsSsSwapmerge mirrors ss_swapmerge: the divide-and-conquer block merge
// that ties dsSsMergeforward/dsSsMergebackward/dsSsInplacemerge together
// across the whole sorted-block tree built by dsSssort's blocking loop.
func dsSsSwapmerge(text []byte, pab []int32, sa []int32, first, middle, last, buf, bufsize, depth int) {
	var stack [dsSsSmergeStackSize]dsSsStackEntry
	ssize := 0
	push := func(a, b, c, d int) {
		stack[ssize] = dsSsStackEntry{a, b, c, d}
		ssize++
	}

	check := 0
	for {
		if last-middle <= bufsize {
			if first < middle && middle < last {
				dsSsMergebackward(text, pab, sa, first, middle, last, buf, depth)
			}
			dsSsMergeCheck(text, pab, sa, depth, first, last, check)
			if ssize == 0 {
				return
			}
			ssize--
			e := stack[ssize]
			first, middle, last, check = e.a, e.b, e.c, e.d
			continue
		}

		if middle-first <= bufsize {
			if first < middle {
				dsSsMergeforward(text, pab, sa, first, middle, last, buf, depth)
			}
			dsSsMergeCheck(text, pab, sa, depth, first, last, check)
			if ssize == 0 {
				return
			}
			ssize--
			e := stack[ssize]
			first, middle, last, check = e.a, e.b, e.c, e.d
			continue
		}

		m := 0
		length := middle - first
		if last-middle < length {
			length = last - middle
		}
		half := length >> 1
		for length > 0 {
			if dsSsComparePAB(text, pab, depth, dsGetIdx(sa[middle+m+half]), dsGetIdx(sa[middle-m-half-1])) < 0 {
				m += half + 1
				half -= (length & 1) ^ 1
			}
			length = half
			half >>= 1
		}

		if m > 0 {
			lm := middle - m
			rm := middle + m
			dsSsBlockswap(sa, lm, middle, m)
			l := middle
			r := middle
			next := 0
			if rm < last {
				if sa[rm] < 0 {
					sa[rm] = ^sa[rm]
					if first < lm {
						for {
							l--
							if sa[l] >= 0 {
								break
							}
						}
						next |= 4
					}
					next |= 1
				} else if first < lm {
					for sa[r] < 0 {
						r++
					}
					next |= 2
				}
			}

			if l-first <= last-r {
				push(r, rm, last, (next&3)|(check&4))
				middle, last, check = lm, l, (check&3)|(next&4)
			} else {
				if next&2 != 0 && r == middle {
					next ^= 6
				}
				push(first, lm, l, (check&3)|(next&4))
				first, middle, check = r, rm, (next&3)|(check&4)
			}
		} else {
			if dsSsComparePAB(text, pab, depth, dsGetIdx(sa[middle-1]), int(sa[middle])) == 0 {
				sa[middle] = ^sa[middle]
			}
			dsSsMergeCheck(text, pab, sa, depth, first, last, check)
			if ssize == 0 {
				return
			}
			ssize--
			e := stack[ssize]
			first, middle, last, check = e.a, e.b, e.c, e.d
		}
	}
}

// dsSssort mirrors the top-level sssort(): blocks [first,last) into
// SS_BLOCKSIZE-sized chunks, sorts each with dsSsMintrosort, and merges
// them back together via dsSsSwapmerge (falling back to dsSsInplacemerge
// for any unbuffered leftover tail). lastsuffix mirrors the C parameter:
// true when this bucket's first B*-suffix (in PAb order) is the very last
// B*-suffix in the whole text, which needs special bounded-comparison
// handling since it has no "next" B*-suffix to bound against.
func dsSssort(text []byte, pab []int32, sa []int32, first, last, buf, bufsize, depth, n int, lastsuffix bool) {
	if lastsuffix {
		first++
	}

	var middle, limit int
	if bufsize < dsSSBlocksize && bufsize < last-first {
		limit = dsSsIsqrt(last - first)
		if bufsize < limit {
			if dsSSBlocksize < limit {
				limit = dsSSBlocksize
			}
			buf = last - limit
			middle = last - limit
			bufsize = limit
		} else {
			middle = last
			limit = 0
		}
	} else {
		middle = last
		limit = 0
	}

	a := first
	i := 0
	for dsSSBlocksize < middle-a {
		dsSsMintrosort(text, pab, sa, a, a+dsSSBlocksize, depth)
		curbufsize := last - (a + dsSSBlocksize)
		curbuf := a + dsSSBlocksize
		if curbufsize <= bufsize {
			curbufsize = bufsize
			curbuf = buf
		}
		b := a
		k := dsSSBlocksize
		j := i
		for j&1 != 0 {
			dsSsSwapmerge(text, pab, sa, b-k, b, b+k, curbuf, curbufsize, depth)
			b -= k
			k <<= 1
			j >>= 1
		}
		a += dsSSBlocksize
		i++
	}

	dsSsMintrosort(text, pab, sa, a, middle, depth)
	for k := dsSSBlocksize; i != 0; k, i = k<<1, i>>1 {
		if i&1 != 0 {
			dsSsSwapmerge(text, pab, sa, a-k, a, middle, buf, bufsize, depth)
			a -= k
		}
	}

	if limit != 0 {
		dsSsMintrosort(text, pab, sa, middle, last, depth)
		dsSsInplacemerge(text, pab, sa, first, middle, last, depth)
	}

	if lastsuffix {
		pai0 := int(pab[sa[first-1]])
		pai1 := n - 2
		last1 := sa[first-1]
		a := first
		for a < last && (sa[a] < 0 || dsSsCompare(text, depth, pai0, pai1, int(pab[sa[a]]), int(pab[sa[a]+1])) > 0) {
			sa[a-1] = sa[a]
			a++
		}
		sa[a-1] = last1
	}
}
