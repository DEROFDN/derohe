package astrobwtv3

// Stage-5 merge: radix-sort the emitted records by 3-byte key, then write
// positions per equal-key group — singleton runs copy straight out,
// all-literal groups (<=32) insertion-sort on the stack, 2-run groups do a
// linear merge, and rare larger groups fall back to a bottom-up k-way merge.
// Ported verbatim from Dirtybird-Go-Miner's internal/astrobwt/sa_v114_merge.go
// (MIT), with its v114Stats* telemetry calls dropped (see sa_template.go's
// header).

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

// compareSuffixesAfterKey compares two suffixes whose first 3 bytes (the
// record key) are already known equal.
func compareSuffixesAfterKey(v *stage4View, a, b uint32) int {
	if a == b {
		return 0
	}
	aLen := v.logicalLen - a
	bLen := v.logicalLen - b
	commonWithKey := aLen
	if bLen < commonWithKey {
		commonWithKey = bLen
	}
	if commonWithKey <= 3 {
		if aLen == bLen {
			return 0
		}
		if aLen < bLen {
			return -1
		}
		return 1
	}

	common := commonWithKey - 3
	ap := v.data[a+3:]
	bp := v.data[b+3:]
	if common >= 8 {
		av := binary.BigEndian.Uint64(ap)
		bv := binary.BigEndian.Uint64(bp)
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
		if c := bytes.Compare(ap[8:common], bp[8:common]); c != 0 {
			return c
		}
	} else if c := bytes.Compare(ap[:common], bp[:common]); c != 0 {
		return c
	}
	if aLen == bLen {
		return 0
	}
	if aLen < bLen {
		return -1
	}
	return 1
}

func suffixLessAfterKey(v *stage4View, a, b uint32) bool {
	cmp := compareSuffixesAfterKey(v, a, b)
	if cmp != 0 {
		return cmp < 0
	}
	return a < b
}

// radixSortRunsByStoredKey sorts native little-endian 24-bit keys by running
// stable passes from the lexical last byte to the first. Ping-pongs
// runs<->radixTmp; the result lands in v.runs.
func radixSortRunsByStoredKey(v *templateSAScratch) {
	runs := v.runs
	n := len(runs)
	if n <= 1 {
		return
	}
	tmp := v.radixTmp[:n]

	var counts0, counts1, counts2 [256]uint32
	for i := range runs {
		counts0[runs[i].key&0xff]++
		counts1[(runs[i].key>>8)&0xff]++
		counts2[(runs[i].key>>16)&0xff]++
	}

	var sum uint32
	for i := 0; i < 256; i++ {
		c := counts2[i]
		counts2[i] = sum
		sum += c
	}
	for i := range runs {
		r := runs[i]
		tmp[counts2[(r.key>>16)&0xff]] = r
		counts2[(r.key>>16)&0xff]++
	}

	sum = 0
	for i := 0; i < 256; i++ {
		c := counts1[i]
		counts1[i] = sum
		sum += c
	}
	for i := range tmp {
		r := tmp[i]
		runs[counts1[(r.key>>8)&0xff]] = r
		counts1[(r.key>>8)&0xff]++
	}

	sum = 0
	for i := 0; i < 256; i++ {
		c := counts0[i]
		counts0[i] = sum
		sum += c
	}
	for i := range runs {
		r := runs[i]
		tmp[counts0[r.key&0xff]] = r
		counts0[r.key&0xff]++
	}
	// result is in tmp: swap the buffers (runs keeps len n, radixTmp cap)
	v.runs = tmp
	v.radixTmp = runs[:cap(runs)]
}

func fusedRunPos(arena []uint32, r stage5Run, rel uint32) uint32 {
	begin := r.begin()
	if r.isLiteral() {
		return begin
	}
	return arena[begin+rel]
}

// tryWriteLiteralGroup handles equal-key groups of <=32 all-literal runs
// with a stack insertion sort.
func tryWriteLiteralGroup(view *stage4View, runs []stage5Run, sa []int32, outPos int) (int, bool) {
	count := len(runs)
	if count == 0 || count > 32 {
		return outPos, false
	}
	var positions [32]uint32
	for i := 0; i < count; i++ {
		if !runs[i].isLiteral() {
			return outPos, false
		}
		positions[i] = runs[i].begin()
	}
	for i := 1; i < count; i++ {
		pos := positions[i]
		j := i
		for j > 0 && suffixLessAfterKey(view, pos, positions[j-1]) {
			positions[j] = positions[j-1]
			j--
		}
		positions[j] = pos
	}
	for i := 0; i < count; i++ {
		sa[outPos] = int32(positions[i])
		outPos++
	}
	return outPos, true
}

// tryWriteTwoRuns merges exactly two runs linearly.
func tryWriteTwoRuns(view *stage4View, arena []uint32, runs []stage5Run, sa []int32, outPos int) (int, bool) {
	if len(runs) != 2 {
		return outPos, false
	}
	left, right := runs[0], runs[1]
	leftCount, rightCount := left.count(), right.count()
	var leftRel, rightRel uint32
	for leftRel < leftCount && rightRel < rightCount {
		lpos := fusedRunPos(arena, left, leftRel)
		rpos := fusedRunPos(arena, right, rightRel)
		if suffixLessAfterKey(view, lpos, rpos) {
			sa[outPos] = int32(lpos)
			leftRel++
		} else {
			sa[outPos] = int32(rpos)
			rightRel++
		}
		outPos++
	}
	for leftRel < leftCount {
		sa[outPos] = int32(fusedRunPos(arena, left, leftRel))
		leftRel++
		outPos++
	}
	for rightRel < rightCount {
		sa[outPos] = int32(fusedRunPos(arena, right, rightRel))
		rightRel++
		outPos++
	}
	return outPos, true
}

func mergeSortedPositionsAfterKey(view *stage4View, src []uint32, leftBegin, leftEnd, rightEnd int, dst []uint32, dstBegin int) {
	left, right, out := leftBegin, leftEnd, dstBegin
	for left < leftEnd && right < rightEnd {
		lpos, rpos := src[left], src[right]
		if suffixLessAfterKey(view, lpos, rpos) {
			dst[out] = lpos
			left++
		} else {
			dst[out] = rpos
			right++
		}
		out++
	}
	for left < leftEnd {
		dst[out] = src[left]
		left++
		out++
	}
	for right < rightEnd {
		dst[out] = src[right]
		right++
		out++
	}
}

// mergeEqualKeyRuns: bottom-up pairwise merge of the per-run sorted position
// lists in v.groupPos (lengths in v.runLens); result ends in v.groupPos.
func mergeEqualKeyRuns(view *stage4View, v *templateSAScratch) {
	if len(v.runLens) <= 1 {
		return
	}
	n := len(v.groupPos)
	v.mergePos = v.mergePos[:cap(v.mergePos)]
	src := v.groupPos
	dst := v.mergePos[:n]
	fromGroupPos := true
	for len(v.runLens) > 1 {
		v.nextLens = v.nextLens[:0]
		inBase, outBase := 0, 0
		for i := 0; i < len(v.runLens); i += 2 {
			leftLen := int(v.runLens[i])
			if i+1 == len(v.runLens) {
				copy(dst[outBase:outBase+leftLen], src[inBase:inBase+leftLen])
				v.nextLens = append(v.nextLens, uint32(leftLen))
				inBase += leftLen
				outBase += leftLen
				continue
			}
			rightLen := int(v.runLens[i+1])
			mergeSortedPositionsAfterKey(view, src, inBase, inBase+leftLen, inBase+leftLen+rightLen, dst, outBase)
			v.nextLens = append(v.nextLens, uint32(leftLen+rightLen))
			inBase += leftLen + rightLen
			outBase += leftLen + rightLen
		}
		v.runLens, v.nextLens = v.nextLens, v.runLens
		src, dst = dst, src
		fromGroupPos = !fromGroupPos
	}
	if !fromGroupPos { // final result sits in mergePos; move it back
		copy(v.groupPos[:n], src[:n])
	}
}

// writeFusedRunsToSA sorts the records and writes the final SA positions.
func writeFusedRunsToSA(view *stage4View, v *templateSAScratch, sa []int32) bool {
	radixSortRunsByStoredKey(v)

	// uint32 view of sa: positions < 2^31, so int32/uint32 bits are identical
	// and arena runs can be bulk-copied. buildTemplateSA guarantees len(sa) >= 1.
	saU32 := unsafe.Slice((*uint32)(unsafe.Pointer(&sa[0])), len(sa))

	runs := v.runs
	arena := v.arena
	n := len(runs)
	groupStart := 0
	outPos := 0
	for groupStart < n {
		r0 := runs[groupStart]
		groupEnd := groupStart + 1
		for groupEnd < n && runs[groupEnd].key == r0.key {
			groupEnd++
		}

		if groupEnd == groupStart+1 {
			if r0.packed>>17 == 0 {
				// literal singleton (packed IS the position) — hottest case
				if outPos >= len(saU32) {
					return false
				}
				saU32[outPos] = r0.packed
				outPos++
			} else {
				begin := r0.begin()
				count := r0.count()
				if outPos+int(count) > len(saU32) {
					return false
				}
				outPos += copy(saU32[outPos:], arena[begin:begin+count])
			}
		} else {
			group := runs[groupStart:groupEnd]
			var handled bool
			if outPos, handled = tryWriteLiteralGroup(view, group, sa, outPos); !handled {
				if outPos, handled = tryWriteTwoRuns(view, arena, group, sa, outPos); !handled {
					// rare fallback: expand all positions and k-way merge
					v.groupPos = v.groupPos[:0]
					v.runLens = v.runLens[:0]
					for i := range group {
						count := group[i].count()
						v.runLens = append(v.runLens, count)
						for rel := uint32(0); rel < count; rel++ {
							v.groupPos = append(v.groupPos, fusedRunPos(arena, group[i], rel))
						}
					}
					mergeEqualKeyRuns(view, v)
					if outPos+len(v.groupPos) > len(saU32) {
						return false
					}
					outPos += copy(saU32[outPos:], v.groupPos)
				}
			}
		}
		groupStart = groupEnd
	}

	return outPos == len(sa)
}
