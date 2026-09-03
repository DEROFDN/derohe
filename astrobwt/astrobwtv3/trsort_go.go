package astrobwtv3

// Stage 3, Milestone 3 of the staged Go port of libdivsufsort (see
// divsufsort_go.go's file header for the overall project framing). This
// file is a close, function-by-function translation of trsort.c (Yuta
// Mori, MIT license; unmodified reference at
// assets/tnn-miner/src/crypto/astrobwtv3/trsort.c) -- the Larsson-Sadakane
// tandem-repeat rank-doubling sort that resolves every B*-substring tie
// sssort's bounded-depth comparison could not (see sssort_go.go's file
// header), replacing Milestone 2's full-suffix-comparison fallback.
//
// Translation conventions (established in divsufsort_go.go/sssort_go.go,
// reused here):
//   - SA-domain pointers (first, last, a..f, middle) become plain Go int
//     indices into the one shared sa []int32 slice.
//   - ^x (Go) for C's ~x.
//   - assert() -> comments documenting the invariant, not runtime checks.
//
// New convention specific to this file: the C source distinguishes ISA
// (the base rank array) from ISAd (= ISA + a running "depth" offset that
// doubles each round -- ISAd[x] reads ISA[x+depth]). Rather than a second
// relocating slice, this is represented as one isaTr []int32 slice (always
// offset 0, i.e. plain ISA) plus a separate depth int carried alongside
// wherever the C source threads ISAd through a call: every ISAd[x] becomes
// isaTr[x+depth]; plain ISA[x] (the handful of depth-0 uses in tr_copy/
// tr_partialcopy and the rank-assignment writes) becomes isaTr[x] directly.
// incr (= ISAd-ISA, fixed for one tr_introsort call, used for +incr/-incr
// pointer arithmetic at push/recursion sites) is threaded as a plain int
// alongside a mutable "current depth" variable.
//
// The isaTr slice passed in by divsufsort_go.go must span sa[m:n] (not
// sa[m:m+m]) -- trsort's rank-doubling genuinely uses the region beyond
// the first m slots as scratch (tr_copy/tr_partialcopy write there), it
// is not incidental slack. See divsufsort_go.go's wiring for detail.
//
// STACK_PUSH5/STACK_POP5's C macro body is "if(ssize==0){return;}" for a
// pop against an empty stack -- every pop site below is a potential
// function-exit point, not just a value fetch, exactly as sssort_go.go's
// STACK_POP sites are.
//
// dsTrStackEntry's 5 fields are reused for two logically different stack
// frame shapes, exactly as the C source's single stack[] struct is: the
// "normal" shape (isaDepth, first, last, limit, trlink) used by the
// choose-pivot/sorted-partition paths, and a repurposed shape used by the
// tandem-repeat-partition path to stash a pending tr_copy/tr_partialcopy
// range (fields reused as: [unused], copyA, copyB, partialcopyFlag,
// [unused]) -- field names below always refer to the "normal" shape's
// labels even where a call site is using the repurposed meaning, matching
// the C source's own struct-field reuse.

const (
	dsTrInsertionsortThreshold = 8  // TR_INSERTIONSORT_THRESHOLD
	dsTrStackSize              = 64 // TR_STACKSIZE (32-bit saidx_t build)
)

// dsTrIlg mirrors tr_ilg's 32-bit (non-BUILD_DIVSUFSORT64) branch. Unlike
// dsSsIlg (bounded by SS_BLOCKSIZE=1024), trsort's rank values can be as
// large as m (B*-suffix count, unbounded relative to a fixed block size),
// so the full cascade is needed. Reuses dsSsLgTable (sssort_go.go) --
// byte-for-byte identical to trsort.c's own lg_table, confirmed by direct
// comparison against the C source.
func dsTrIlg(n int) int {
	if n&0xffff0000 != 0 {
		if n&0xff000000 != 0 {
			return 24 + int(dsSsLgTable[(n>>24)&0xff])
		}
		return 16 + int(dsSsLgTable[(n>>16)&0xff])
	}
	if n&0x0000ff00 != 0 {
		return 8 + int(dsSsLgTable[(n>>8)&0xff])
	}
	return int(dsSsLgTable[n&0xff])
}

// dsTrInsertionsort mirrors tr_insertionsort.
func dsTrInsertionsort(isaTr []int32, depth int, sa []int32, first, last int) {
	isad := func(v int32) int32 { return isaTr[int(v)+depth] }
	for a := first + 1; a < last; a++ {
		t := sa[a]
		b := a - 1
		r := isad(t) - isad(sa[b])
		for r < 0 {
			for {
				sa[b+1] = sa[b]
				b--
				if !(b >= first && sa[b] < 0) {
					break
				}
			}
			if b < first {
				break
			}
			r = isad(t) - isad(sa[b])
		}
		if r == 0 {
			sa[b] = ^sa[b]
		}
		sa[b+1] = t
	}
}

// dsTrFixdown mirrors tr_fixdown. Deliberately does not add an explicit
// j+1<size bound check on the right-child read (the C source doesn't
// either): tr_heapsort only ever calls this with an odd heap size, which
// guarantees a left child in bounds implies its sibling is too.
func dsTrFixdown(isaTr []int32, depth int, sa []int32, base, i, size int) {
	isad := func(v int32) int32 { return isaTr[int(v)+depth] }
	v := sa[base+i]
	c := isad(v)
	for {
		j := 2*i + 1
		if j >= size {
			break
		}
		k := j
		j++
		d := isad(sa[base+k])
		if e := isad(sa[base+j]); d < e {
			k = j
			d = e
		}
		if d <= c {
			break
		}
		sa[base+i] = sa[base+k]
		i = k
	}
	sa[base+i] = v
}

// dsTrHeapsort mirrors tr_heapsort.
func dsTrHeapsort(isaTr []int32, depth int, sa []int32, base, size int) {
	isad := func(v int32) int32 { return isaTr[int(v)+depth] }
	m := size
	if size%2 == 0 {
		m--
		if isad(sa[base+m/2]) < isad(sa[base+m]) {
			sa[base+m], sa[base+m/2] = sa[base+m/2], sa[base+m]
		}
	}
	for i := m/2 - 1; i >= 0; i-- {
		dsTrFixdown(isaTr, depth, sa, base, i, m)
	}
	if size%2 == 0 {
		sa[base+0], sa[base+m] = sa[base+m], sa[base+0]
		dsTrFixdown(isaTr, depth, sa, base, 0, m)
	}
	for i := m - 1; i > 0; i-- {
		t := sa[base+0]
		sa[base+0] = sa[base+i]
		dsTrFixdown(isaTr, depth, sa, base, 0, i)
		sa[base+i] = t
	}
}

// dsTrMedian3 mirrors tr_median3. v1/v2/v3 are sa-indices; the swaps here
// exchange which index is being referred to, matching the C source's
// pointer-variable SWAP (not an array-value swap).
func dsTrMedian3(isaTr []int32, depth int, sa []int32, v1, v2, v3 int) int {
	isad := func(v int) int32 { return isaTr[int(sa[v])+depth] }
	if isad(v1) > isad(v2) {
		v1, v2 = v2, v1
	}
	if isad(v2) > isad(v3) {
		if isad(v1) > isad(v3) {
			return v1
		}
		return v3
	}
	return v2
}

// dsTrMedian5 mirrors tr_median5, same index-swap convention as dsTrMedian3.
func dsTrMedian5(isaTr []int32, depth int, sa []int32, v1, v2, v3, v4, v5 int) int {
	isad := func(v int) int32 { return isaTr[int(sa[v])+depth] }
	if isad(v2) > isad(v3) {
		v2, v3 = v3, v2
	}
	if isad(v4) > isad(v5) {
		v4, v5 = v5, v4
	}
	if isad(v2) > isad(v4) {
		v2, v4 = v4, v2
		v3, v5 = v5, v3
	}
	if isad(v1) > isad(v3) {
		v1, v3 = v3, v1
	}
	if isad(v1) > isad(v4) {
		v1, v4 = v4, v1
		v3, v5 = v5, v3
	}
	if isad(v3) > isad(v4) {
		return v4
	}
	return v3
}

// dsTrPivot mirrors tr_pivot.
func dsTrPivot(isaTr []int32, depth int, sa []int32, first, last int) int {
	t := last - first
	middle := first + t/2
	if t <= 512 {
		if t <= 32 {
			return dsTrMedian3(isaTr, depth, sa, first, middle, last-1)
		}
		t >>= 2
		return dsTrMedian5(isaTr, depth, sa, first, first+t, middle, last-1-t, last-1)
	}
	t >>= 3
	first = dsTrMedian3(isaTr, depth, sa, first, first+t, first+(t<<1))
	middle = dsTrMedian3(isaTr, depth, sa, middle-t, middle, middle+t)
	last = dsTrMedian3(isaTr, depth, sa, last-1-(t<<1), last-1-t, last-1)
	return dsTrMedian3(isaTr, depth, sa, first, middle, last)
}

// dsTrBudget mirrors trbudget_t: a chance/remain/incval/count-based gate
// that forces a heapsort fallback once too many recursion "chances" have
// been spent, bounding tr_introsort's worst case for adversarial input.
type dsTrBudget struct {
	chance, remain, incval, count int
}

func dsTrBudgetInit(b *dsTrBudget, chance, incval int) {
	b.chance = chance
	b.remain = incval
	b.incval = incval
}

func dsTrBudgetCheck(b *dsTrBudget, size int) bool {
	if size <= b.remain {
		b.remain -= size
		return true
	}
	if b.chance == 0 {
		b.count += size
		return false
	}
	b.remain += b.incval - size
	b.chance--
	return true
}

// dsTrPartition mirrors tr_partition: three-way partition of sa[first:last]
// against threshold value v (using ISAd-depth ranks), returning the [a,b)
// range of elements equal to v.
func dsTrPartition(isaTr []int32, depth int, sa []int32, first, middle, last int, v int32) (int, int) {
	isad := func(idx int) int32 { return isaTr[int(sa[idx])+depth] }
	var x int32

	b := middle - 1
	for {
		b++
		if !(b < last) {
			break
		}
		x = isad(b)
		if x != v {
			break
		}
	}
	a := b
	if a < last && x < v {
		for {
			b++
			if !(b < last) {
				break
			}
			x = isad(b)
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
		if !(b < c) {
			break
		}
		x = isad(c)
		if x != v {
			break
		}
	}
	d := c
	if b < d && x > v {
		for {
			c--
			if !(b < c) {
				break
			}
			x = isad(c)
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
			if !(b < c) {
				break
			}
			x = isad(b)
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
			if !(b < c) {
				break
			}
			x = isad(c)
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
		first += b - a
		last -= d - c
	}
	return first, last
}

// dsTrCopy mirrors tr_copy: propagates already-known ranks for the middle
// (tandem-repeat) partition using the sorted order of its neighboring
// partitions. isaTr here is always accessed at depth-0 (plain ISA in the
// C source, not ISAd) -- depth is a separate plain-int arithmetic operand
// (subtracted from sa values to look up the shifted suffix), matching the
// C source's own distinct use of "depth" here.
func dsTrCopy(isaTr []int32, sa []int32, first, a, b, last, depth int) {
	v := b - 1
	c := first
	d := a - 1
	for c <= d {
		s := int(sa[c]) - depth
		if s >= 0 && int(isaTr[s]) == v {
			d++
			sa[d] = int32(s)
			isaTr[s] = int32(d)
		}
		c++
	}
	c = last - 1
	e := d + 1
	d = b
	for e < d {
		s := int(sa[c]) - depth
		if s >= 0 && int(isaTr[s]) == v {
			d--
			sa[d] = int32(s)
			isaTr[s] = int32(d)
		}
		c--
	}
}

// dsTrPartialcopy mirrors tr_partialcopy: like dsTrCopy, but for the case
// where the middle partition's budget was exhausted -- it must compress
// consecutive equal ranks down to a single representative slot instead of
// assigning every element its own final rank.
func dsTrPartialcopy(isaTr []int32, sa []int32, first, a, b, last, depth int) {
	v := b - 1
	lastrank := -1
	newrank := -1
	c := first
	d := a - 1
	for c <= d {
		s := int(sa[c]) - depth
		if s >= 0 && int(isaTr[s]) == v {
			d++
			sa[d] = int32(s)
			rank := int(isaTr[s+depth])
			if lastrank != rank {
				lastrank = rank
				newrank = d
			}
			isaTr[s] = int32(newrank)
		}
		c++
	}

	lastrank = -1
	for e := d; first <= e; e-- {
		rank := int(isaTr[sa[e]])
		if lastrank != rank {
			lastrank = rank
			newrank = e
		}
		if newrank != rank {
			isaTr[sa[e]] = int32(newrank)
		}
	}

	lastrank = -1
	c = last - 1
	e := d + 1
	d = b
	for e < d {
		s := int(sa[c]) - depth
		if s >= 0 && int(isaTr[s]) == v {
			d--
			sa[d] = int32(s)
			rank := int(isaTr[s+depth])
			if lastrank != rank {
				lastrank = rank
				newrank = d
			}
			isaTr[s] = int32(newrank)
		}
		c--
	}
}

// dsTrStackEntry mirrors tr_introsort's local stack{} tuple -- see the
// file header for the two different field-shape interpretations it's used
// with (matching the C source's own struct-field reuse).
type dsTrStackEntry struct {
	isaDepth, first, last, limit, trlink int
}

// dsTrIntrosort mirrors tr_introsort: bounded-depth introsort over
// sa[first:last], using ISA-rank comparisons (via isaTr at the running
// depth) instead of text bytes, with a budget-gated heapsort fallback and
// a "tandem repeat partition" branch (limit==-1) that is the actual
// Larsson-Sadakane doubling step -- partitioning by "is this suffix's
// rank already fully determined" rather than by a text comparison.
func dsTrIntrosort(isaTr []int32, isaDepth int, sa []int32, first, last int, budget *dsTrBudget) {
	var stack [dsTrStackSize]dsTrStackEntry
	ssize := 0
	push := func(a, b, c, d, e int) {
		stack[ssize] = dsTrStackEntry{a, b, c, d, e}
		ssize++
	}

	curDepth := isaDepth
	incr := isaDepth
	limit := dsTrIlg(last - first)
	trlink := -1

	for {
		if limit < 0 {
			if limit == -1 {
				// tandem repeat partition
				a, b := dsTrPartition(isaTr, curDepth-incr, sa, first, first, last, int32(last-1))

				if a < last {
					v := int32(a - 1)
					for c := first; c < a; c++ {
						isaTr[sa[c]] = v
					}
				}
				if b < last {
					v := int32(b - 1)
					for c := a; c < b; c++ {
						isaTr[sa[c]] = v
					}
				}

				if b-a > 1 {
					push(0, a, b, 0, 0)
					push(curDepth-incr, first, last, -2, trlink)
					trlink = ssize - 2
				}
				if a-first <= last-b {
					if a-first > 1 {
						push(curDepth, b, last, dsTrIlg(last-b), trlink)
						last, limit = a, dsTrIlg(a-first)
					} else if last-b > 1 {
						first, limit = b, dsTrIlg(last-b)
					} else {
						if ssize == 0 {
							return
						}
						ssize--
						e := stack[ssize]
						curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
					}
				} else {
					if last-b > 1 {
						push(curDepth, first, a, dsTrIlg(a-first), trlink)
						first, limit = b, dsTrIlg(last-b)
					} else if a-first > 1 {
						last, limit = a, dsTrIlg(a-first)
					} else {
						if ssize == 0 {
							return
						}
						ssize--
						e := stack[ssize]
						curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
					}
				}
			} else if limit == -2 {
				// tandem repeat copy
				ssize--
				ta := stack[ssize].first
				tb := stack[ssize].last
				if stack[ssize].limit == 0 {
					dsTrCopy(isaTr, sa, first, ta, tb, last, curDepth)
				} else {
					if trlink >= 0 {
						stack[trlink].limit = -1
					}
					dsTrPartialcopy(isaTr, sa, first, ta, tb, last, curDepth)
				}
				if ssize == 0 {
					return
				}
				ssize--
				e := stack[ssize]
				curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
			} else {
				// sorted partition
				if sa[first] >= 0 {
					a := first
					for {
						isaTr[sa[a]] = int32(a)
						a++
						if !(a < last && sa[a] >= 0) {
							break
						}
					}
					first = a
				}
				if first < last {
					a := first
					for {
						sa[a] = ^sa[a]
						a++
						if !(sa[a] < 0) {
							break
						}
					}
					var next int
					if isaTr[sa[a]] != isaTr[int(sa[a])+curDepth] {
						next = dsTrIlg(a - first + 1)
					} else {
						next = -1
					}
					a++
					if a < last {
						v := int32(a - 1)
						for b := first; b < a; b++ {
							isaTr[sa[b]] = v
						}
					}

					if dsTrBudgetCheck(budget, a-first) {
						if a-first <= last-a {
							push(curDepth, a, last, -3, trlink)
							curDepth += incr
							last, limit = a, next
						} else {
							if last-a > 1 {
								push(curDepth+incr, first, a, next, trlink)
								first, limit = a, -3
							} else {
								curDepth += incr
								last, limit = a, next
							}
						}
					} else {
						if trlink >= 0 {
							stack[trlink].limit = -1
						}
						if last-a > 1 {
							first, limit = a, -3
						} else {
							if ssize == 0 {
								return
							}
							ssize--
							e := stack[ssize]
							curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
						}
					}
				} else {
					if ssize == 0 {
						return
					}
					ssize--
					e := stack[ssize]
					curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
				}
			}
			continue
		}

		if last-first <= dsTrInsertionsortThreshold {
			dsTrInsertionsort(isaTr, curDepth, sa, first, last)
			limit = -3
			continue
		}

		oldLimit := limit
		limit--
		if oldLimit == 0 {
			dsTrHeapsort(isaTr, curDepth, sa, first, last-first)
			for a := last - 1; first < a; {
				x := isaTr[int(sa[a])+curDepth]
				b := a - 1
				for first <= b && isaTr[int(sa[b])+curDepth] == x {
					sa[b] = ^sa[b]
					b--
				}
				a = b
			}
			limit = -3
			continue
		}

		// choose pivot
		pivot := dsTrPivot(isaTr, curDepth, sa, first, last)
		sa[first], sa[pivot] = sa[pivot], sa[first]
		v := isaTr[int(sa[first])+curDepth]

		// partition
		a, b := dsTrPartition(isaTr, curDepth, sa, first, first+1, last, v)
		if last-first != b-a {
			var next int
			if isaTr[sa[a]] != v {
				next = dsTrIlg(b - a)
			} else {
				next = -1
			}

			{
				rv := int32(a - 1)
				for c := first; c < a; c++ {
					isaTr[sa[c]] = rv
				}
			}
			if b < last {
				rv := int32(b - 1)
				for c := a; c < b; c++ {
					isaTr[sa[c]] = rv
				}
			}

			if b-a > 1 && dsTrBudgetCheck(budget, b-a) {
				if a-first <= last-b {
					if last-b <= b-a {
						if a-first > 1 {
							push(curDepth+incr, a, b, next, trlink)
							push(curDepth, b, last, limit, trlink)
							last = a
						} else if last-b > 1 {
							push(curDepth+incr, a, b, next, trlink)
							first = b
						} else {
							curDepth += incr
							first, last, limit = a, b, next
						}
					} else if a-first <= b-a {
						if a-first > 1 {
							push(curDepth, b, last, limit, trlink)
							push(curDepth+incr, a, b, next, trlink)
							last = a
						} else {
							push(curDepth, b, last, limit, trlink)
							curDepth += incr
							first, last, limit = a, b, next
						}
					} else {
						push(curDepth, b, last, limit, trlink)
						push(curDepth, first, a, limit, trlink)
						curDepth += incr
						first, last, limit = a, b, next
					}
				} else {
					if a-first <= b-a {
						if last-b > 1 {
							push(curDepth+incr, a, b, next, trlink)
							push(curDepth, first, a, limit, trlink)
							first = b
						} else if a-first > 1 {
							push(curDepth+incr, a, b, next, trlink)
							last = a
						} else {
							curDepth += incr
							first, last, limit = a, b, next
						}
					} else if last-b <= b-a {
						if last-b > 1 {
							push(curDepth, first, a, limit, trlink)
							push(curDepth+incr, a, b, next, trlink)
							first = b
						} else {
							push(curDepth, first, a, limit, trlink)
							curDepth += incr
							first, last, limit = a, b, next
						}
					} else {
						push(curDepth, first, a, limit, trlink)
						push(curDepth, b, last, limit, trlink)
						curDepth += incr
						first, last, limit = a, b, next
					}
				}
			} else {
				if b-a > 1 && trlink >= 0 {
					stack[trlink].limit = -1
				}
				if a-first <= last-b {
					if a-first > 1 {
						push(curDepth, b, last, limit, trlink)
						last = a
					} else if last-b > 1 {
						first = b
					} else {
						if ssize == 0 {
							return
						}
						ssize--
						e := stack[ssize]
						curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
					}
				} else {
					if last-b > 1 {
						push(curDepth, first, a, limit, trlink)
						first = b
					} else if a-first > 1 {
						last = a
					} else {
						if ssize == 0 {
							return
						}
						ssize--
						e := stack[ssize]
						curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
					}
				}
			}
		} else {
			if dsTrBudgetCheck(budget, last-first) {
				limit = dsTrIlg(last - first)
				curDepth += incr
			} else {
				if trlink >= 0 {
					stack[trlink].limit = -1
				}
				if ssize == 0 {
					return
				}
				ssize--
				e := stack[ssize]
				curDepth, first, last, limit, trlink = e.isaDepth, e.first, e.last, e.limit, e.trlink
			}
		}
	}
}

// dsTrsort mirrors trsort: the top-level Larsson-Sadakane rank-doubling
// loop. isaTr must be the full sa[m:n] window (see file header), sa the
// shared backing slice (sa[0:m] holding the compact-index working set
// produced by dsComputeBStarRanks's skip-marker encoding), m the B*-suffix
// count (trsort.c's own "n" parameter -- named m here to avoid confusion
// with the surrounding package's n=len(text)), and depth the starting
// comparison depth (1, from divsufsort.c's trsort(ISAb, SA, m, 1) call).
func dsTrsort(isaTr []int32, sa []int32, m, depth int) {
	var budget dsTrBudget
	dsTrBudgetInit(&budget, dsTrIlg(m)*2/3, m)

	curDepth := depth
	for -m < int(sa[0]) {
		first := 0
		skip := 0
		unsorted := 0
		for {
			t := sa[first]
			if t < 0 {
				first -= int(t)
				skip += int(t)
			} else {
				if skip != 0 {
					sa[first+skip] = int32(skip)
					skip = 0
				}
				last := int(isaTr[t]) + 1
				if last-first > 1 {
					budget.count = 0
					dsTrIntrosort(isaTr, curDepth, sa, first, last, &budget)
					if budget.count != 0 {
						unsorted += budget.count
					} else {
						skip = first - last
					}
				} else if last-first == 1 {
					skip = -1
				}
				first = last
			}
			if !(first < m) {
				break
			}
		}
		if skip != 0 {
			sa[first+skip] = int32(skip)
		}
		if unsorted == 0 {
			break
		}
		curDepth += curDepth
	}
}
