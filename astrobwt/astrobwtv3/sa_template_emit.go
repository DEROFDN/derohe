package astrobwtv3

// Stage-4 emit: for each template run of k full 256-byte groups, sort the k
// column-255 suffixes outright, then induce columns 254..0 (decrement each
// position; stable first-byte insertion re-sort), emitting one record per
// (column x equal-3-byte-key group). Ported verbatim from
// Dirtybird-Go-Miner's internal/astrobwt/sa_v114_emit.go (MIT), with its
// v114Stats* telemetry calls dropped (separate observability subsystem, out
// of scope for this port — see sa_template.go's header).

import (
	"bytes"
	"unsafe"
)

// compareSuffixes is the stage-4 suffix compare (shorter suffix wins on a
// common-prefix tie — exactly bytes.Compare on the two suffix slices, which
// runs as vectorized asm). Wolf output is highly repetitive, so compares
// routinely scan long common prefixes.
func compareSuffixes(v *stage4View, a, b uint32) int {
	if a == b {
		return 0
	}
	return bytes.Compare(v.data[a:v.logicalLen], v.data[b:v.logicalLen])
}

// sortSuffixOrderSmall: insertion sort by full suffix compare (short runs).
func sortSuffixOrderSmall(v *stage4View, order []uint32) {
	for i := 1; i < len(order); i++ {
		pos := order[i]
		j := i
		for j > 0 && compareSuffixes(v, pos, order[j-1]) < 0 {
			order[j] = order[j-1]
			j--
		}
		order[j] = pos
	}
}

// heapSortSuffixOrder replaces std::sort for long runs without allocating
// (suffix compare is a strict total order on distinct positions).
func heapSortSuffixOrder(v *stage4View, order []uint32) {
	n := len(order)
	for i := n/2 - 1; i >= 0; i-- {
		siftDownSuffix(v, order, i, n)
	}
	for i := n - 1; i > 0; i-- {
		order[0], order[i] = order[i], order[0]
		siftDownSuffix(v, order, 0, i)
	}
}

func siftDownSuffix(v *stage4View, order []uint32, root, n int) {
	for {
		child := 2*root + 1
		if child >= n {
			return
		}
		if child+1 < n && compareSuffixes(v, order[child], order[child+1]) < 0 {
			child++
		}
		if compareSuffixes(v, order[root], order[child]) >= 0 {
			return
		}
		order[root], order[child] = order[child], order[root]
		root = child
	}
}

// appendOrderGroup ports append_fused_order_group with
// count1_singletons=false (the faithful-port default): singletons become
// literal runs, multi-position groups spill their positions to the arena.
func appendOrderGroup(v *templateSAScratch, key uint32, order []uint32, first, count uint32) bool {
	if count == 0 {
		return false
	}
	if count == 1 {
		v.runs = append(v.runs, stage5Run{key: key, packed: order[first]})
		return true
	}
	begin := uint32(len(v.arena))
	if begin > templateArenaCapacity || count > templateArenaCapacity-begin {
		return false
	}
	v.arena = append(v.arena, order[first:first+count]...)
	v.runs = append(v.runs, stage5Run{key: key, packed: count<<17 + begin})
	return true
}

// emitLiteralRecords: one singleton record per position (single-group
// templates and the partial tail group). Appends records directly — no
// per-position appendOrderGroup call or stack array; unchecked 24-bit key
// loads (positions < logicalLen, 4 zeroed padding bytes past it, ensured by
// buildTemplateSA).
func emitLiteralRecords(view *stage4View, start, count uint32, v *templateSAScratch) bool {
	dp := unsafe.Pointer(&view.data[0])
	runs := v.runs
	for rel := uint32(0); rel < count; rel++ {
		pos := start + rel
		key := *(*uint32)(unsafe.Add(dp, pos)) & 0xffffff
		runs = append(runs, stage5Run{key: key, packed: pos})
	}
	v.runs = runs
	return true
}

// emitFullGroupRunTwo: the k==2 specialization, with the singleton/two-run
// appends inlined and unchecked key loads.
func emitFullGroupRunTwo(view *stage4View, startGroup uint32, v *templateSAScratch) bool {
	base := startGroup << 8
	var order [2]uint32
	order[0], order[1] = base+255, base+511
	if compareSuffixes(view, order[1], order[0]) < 0 {
		order[0], order[1] = order[1], order[0]
	}

	dp := unsafe.Pointer(&view.data[0])
	for rel := 255; rel >= 0; rel-- {
		key0 := *(*uint32)(unsafe.Add(dp, order[0])) & 0xffffff
		key1 := *(*uint32)(unsafe.Add(dp, order[1])) & 0xffffff
		if key0 == key1 {
			begin := uint32(len(v.arena))
			if begin > templateArenaCapacity || 2 > templateArenaCapacity-begin {
				return false
			}
			v.arena = append(v.arena, order[0], order[1])
			v.runs = append(v.runs, stage5Run{key: key0, packed: 2<<17 + begin})
		} else {
			v.runs = append(v.runs,
				stage5Run{key: key0, packed: order[0]},
				stage5Run{key: key1, packed: order[1]})
		}
		if rel > 0 {
			order[0]--
			order[1]--
			if *(*byte)(unsafe.Add(dp, order[0])) > *(*byte)(unsafe.Add(dp, order[1])) {
				order[0], order[1] = order[1], order[0]
			}
		}
	}
	return true
}

// emitFullGroupRunGeneric covers k>=3: full sort of the column-255 suffixes,
// then per-column key grouping and stable first-byte induction. The
// reference splits this into short(<=25)/fixed<3,4>/general variants purely
// as manual specializations of the same algorithm; one parameterized loop is
// behavior-identical.
func emitFullGroupRunGeneric(view *stage4View, startGroup, groupCount uint32, v *templateSAScratch) bool {
	base := startGroup << 8
	// int counters + len-capped slices: the prove pass can then discharge the
	// order[]/keys[] bounds checks in the per-column loops (one IsSliceInBounds
	// each here instead of checks all over the induction re-sort).
	gc := int(groupCount)
	order := v.order[:gc:gc]
	for chunk := 0; chunk < gc; chunk++ {
		order[chunk] = base + uint32(chunk)<<8 + 255
	}
	if groupCount <= stage4ShortRunMax {
		sortSuffixOrderSmall(view, order)
	} else {
		heapSortSuffixOrder(view, order)
	}

	// All positions in order stay < logicalLen <= len(data)-4 throughout, so
	// the hot per-column loops read data through unchecked pointers.
	dp := unsafe.Pointer(&view.data[0])

	// keys[i] is kept equal to the 24-bit key at order[i] across columns: the
	// induction step derives the next key from the current one plus ONE new
	// byte (little-endian: key(pos-1) = data[pos-1] | key(pos)<<8 truncated),
	// so only column 255 pays full key loads, and the re-sort compares
	// in-array first bytes instead of random data reads.
	var keysArr [stage4MaxGroupRun]uint32
	keys := keysArr[:gc]
	for i := range keys {
		keys[i] = *(*uint32)(unsafe.Add(dp, order[i])) & 0xffffff
	}

	for rel := 255; rel >= 0; rel-- {
		groupStart := 0
		for groupStart < gc {
			key := keys[groupStart]
			groupEnd := groupStart + 1
			for groupEnd < gc && keys[groupEnd] == key {
				groupEnd++
			}
			if groupEnd == groupStart+1 {
				// singleton fast path (most groups); avoids the call
				v.runs = append(v.runs, stage5Run{key: key, packed: order[groupStart]})
			} else if !appendOrderGroup(v, key, order, uint32(groupStart), uint32(groupEnd-groupStart)) {
				return false
			}
			groupStart = groupEnd
		}

		if rel > 0 {
			// decrement + key derivation fused into the stable first-byte
			// insertion re-sort (the induction step): entries [0,i) are
			// already decremented, re-keyed, and sorted when i is placed.
			pos0 := order[0] - 1
			order[0] = pos0
			keys[0] = uint32(*(*byte)(unsafe.Add(dp, pos0))) | keys[0]<<8&0xffff00
			for i := 1; i < gc; i++ {
				pos := order[i] - 1
				b := uint32(*(*byte)(unsafe.Add(dp, pos)))
				nk := b | keys[i]<<8&0xffff00
				j := i
				for j > 0 && keys[j-1]&0xff > b {
					order[j] = order[j-1]
					keys[j] = keys[j-1]
					j--
				}
				order[j] = pos
				keys[j] = nk
			}
		}
	}
	return true
}

// emitFullGroupRun dispatches one template run [startGroup, endGroup).
func emitFullGroupRun(view *stage4View, startGroup, endGroup uint32, v *templateSAScratch) bool {
	groupCount := endGroup - startGroup
	if groupCount == 0 {
		return true
	}
	if groupCount > stage4MaxGroupRun {
		return false
	}
	if groupCount == 1 {
		return emitLiteralRecords(view, startGroup<<8, 256, v)
	}
	if groupCount == 2 {
		return emitFullGroupRunTwo(view, startGroup, v)
	}
	return emitFullGroupRunGeneric(view, startGroup, groupCount, v)
}
