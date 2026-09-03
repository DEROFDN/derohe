//go:build astrobwt_capture

package astrobwtv3

// ScratchCaptureHook, if non-nil, is called with a copy of scratch.data
// (truncated to dataLen) immediately before suffix-array construction, only
// when built with the astrobwt_capture tag. Used by the fixture generator
// (sa_fixture_gen_test.go) to extract realistic ~64-70KB suffix-array-
// construction inputs from real, unmodified AstroBWTv3() runs -- so
// benchmark/oracle fixtures are authentic rather than synthetically
// reconstructed. Nil by default; the generator sets it before calling
// AstroBWTv3().
var ScratchCaptureHook func(data []byte, dataLen uint32)

func maybeCaptureScratch(data []byte, dataLen uint32) {
	if ScratchCaptureHook == nil {
		return
	}
	// data aliases scratch.data, which is reused (sync.Pool) as soon as this
	// call returns, so the hook needs its own copy.
	cp := make([]byte, len(data))
	copy(cp, data)
	ScratchCaptureHook(cp, dataLen)
}

// ScratchCaptureTemplateHook is ScratchCaptureHook's sibling for the
// template-descriptor SA path (sa_template.go): the existing
// testdata/safixtures corpus predates scratch.markers/nTemplates, so
// buildTemplateSA can't run on it directly — it needs real markers from a
// real wolf-loop run, not just scratch.data. Used by
// sa_template_fixture_gen_test.go to build a separate, marker-aware corpus.
// Nil by default; fires from the same call site as ScratchCaptureHook, after
// pow.go's wolf loop has finished writing markers/nTemplates.
var ScratchCaptureTemplateHook func(data []byte, dataLen uint32, markers []uint16, nTemplates uint32)

func maybeCaptureScratchTemplate(data []byte, dataLen uint32, markers []uint16, nTemplates uint32) {
	if ScratchCaptureTemplateHook == nil {
		return
	}
	cpData := make([]byte, len(data))
	copy(cpData, data)
	cpMarkers := make([]uint16, nTemplates)
	copy(cpMarkers, markers[:nTemplates])
	ScratchCaptureTemplateHook(cpData, dataLen, cpMarkers, nTemplates)
}
