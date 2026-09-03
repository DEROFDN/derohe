//go:build !astrobwt_capture

package astrobwtv3

// maybeCaptureScratch is a no-op in normal builds (including the miner and
// any node binary) -- it inlines away entirely. The real implementation
// only exists under the astrobwt_capture build tag, used to generate
// realistic ~64-70KB benchmark/oracle fixtures from actual AstroBWTv3 runs.
// See sa_capture_hook.go.
func maybeCaptureScratch(data []byte, dataLen uint32) {}

// maybeCaptureScratchTemplate is maybeCaptureScratch's sibling stub; see
// sa_capture_hook.go's ScratchCaptureTemplateHook.
func maybeCaptureScratchTemplate(data []byte, dataLen uint32, markers []uint16, nTemplates uint32) {}
