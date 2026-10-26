package hf4archive

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzDecodeStrictJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"schema_version":1}`),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`{"a":1}{"b":2}`),
		[]byte("{\"a\":1}\n"),
		[]byte(``),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var manifest Manifest
		_ = decodeStrictJSON(data, &manifest)
	})
}

func FuzzScanArchiveJSONL(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("{\"a\":1}\n"),
		[]byte(""),
		[]byte("\n"),
		[]byte("{\"a\":1}"),
		[]byte("{\"a\":1}\r\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Split(scanArchiveJSONL)
		scanner.Buffer(make([]byte, 1024), 1<<20)
		for scanner.Scan() {
		}
	})
}

func FuzzValidateEndpointLabel(f *testing.F) {
	for _, seed := range []string{
		"https://example.org/archive",
		"http://127.0.0.1/",
		"ipfs://bafyexample",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = validateEndpointLabel(value)
	})
}
