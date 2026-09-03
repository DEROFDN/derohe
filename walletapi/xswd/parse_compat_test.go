package xswd

import "testing"

// TestParseRequestsCompat pins the set of message shapes XSWD accepts.
//
// jrpc2 v1 validates each message and drops any it flags, which would silently
// stop serving shapes XSWD has always served (scalar params, extra fields,
// non-string ids). A dependency bump that reintroduces that narrowing compiles
// clean, so this test is the guard. Expectations were taken from the jrpc2
// version derohe vendored before the upgrade, by differential test.
func TestParseRequestsCompat(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		wantErr bool
		wantN   int
		wantID  string
		wantMet string
		wantPar string
	}{
		{name: "scalar string params", msg: `{"jsonrpc":"2.0","id":1,"method":"SignData","params":"aGVsbG8="}`,
			wantN: 1, wantID: "1", wantMet: "SignData", wantPar: `"aGVsbG8="`},
		{name: "scalar number params", msg: `{"jsonrpc":"2.0","id":1,"method":"SignData","params":123}`,
			wantN: 1, wantID: "1", wantMet: "SignData", wantPar: "123"},
		{name: "object params", msg: `{"jsonrpc":"2.0","id":1,"method":"GetAddress","params":{}}`,
			wantN: 1, wantID: "1", wantMet: "GetAddress", wantPar: "{}"},
		{name: "array params", msg: `{"jsonrpc":"2.0","id":1,"method":"GetAddress","params":[1,2]}`,
			wantN: 1, wantID: "1", wantMet: "GetAddress", wantPar: "[1,2]"},
		{name: "extra field", msg: `{"jsonrpc":"2.0","id":1,"method":"GetAddress","extra":"x"}`,
			wantN: 1, wantID: "1", wantMet: "GetAddress"},
		{name: "mixed request and reply fields", msg: `{"jsonrpc":"2.0","id":1,"method":"GetAddress","result":5}`,
			wantN: 1, wantID: "1", wantMet: "GetAddress"},
		{name: "string id", msg: `{"jsonrpc":"2.0","id":"1","method":"GetAddress"}`,
			wantN: 1, wantID: `"1"`, wantMet: "GetAddress"},
		{name: "double quoted id", msg: `{"jsonrpc":"2.0","id":"\"1\"","method":"GetAddress"}`,
			wantN: 1, wantID: `"\"1\""`, wantMet: "GetAddress"},
		{name: "non numeric string id", msg: `{"jsonrpc":"2.0","id":"7f3a-bc12","method":"GetAddress"}`,
			wantN: 1, wantID: `"7f3a-bc12"`, wantMet: "GetAddress"},
		{name: "garbage id", msg: `{"jsonrpc":"2.0","id":true,"method":"GetAddress"}`,
			wantN: 1, wantMet: "GetAddress"},
		{name: "batch", msg: `[{"jsonrpc":"2.0","id":1,"method":"A"},{"jsonrpc":"2.0","id":2,"method":"B"}]`,
			wantN: 2, wantID: "1", wantMet: "A"},
		{name: "empty batch", msg: `[]`, wantN: 0},

		// only a missing or invalid version marker is an error, plus malformed JSON
		{name: "missing version", msg: `{"id":1,"method":"GetAddress"}`, wantErr: true},
		{name: "wrong version", msg: `{"jsonrpc":"1.0","id":1,"method":"GetAddress"}`, wantErr: true},
		{name: "non string version", msg: `{"jsonrpc":2.0,"id":1,"method":"GetAddress"}`, wantErr: true},
		{name: "batch with one bad version", msg: `[{"jsonrpc":"2.0","id":1,"method":"A"},{"jsonrpc":"1.0","id":2,"method":"B"}]`, wantErr: true},
		{name: "not json", msg: `{`, wantErr: true},
		{name: "json string", msg: `"hello"`, wantErr: true},
		{name: "empty input", msg: ``, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRequestsCompat([]byte(tt.msg))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %d requests", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantN {
				t.Fatalf("got %d requests, want %d", len(got), tt.wantN)
			}
			if tt.wantN == 0 {
				return
			}
			if got[0] == nil {
				t.Fatal("request was dropped, XSWD would dereference nil")
			}
			if got[0].ID() != tt.wantID {
				t.Errorf("id = %q, want %q", got[0].ID(), tt.wantID)
			}
			if got[0].Method() != tt.wantMet {
				t.Errorf("method = %q, want %q", got[0].Method(), tt.wantMet)
			}
			if got[0].ParamString() != tt.wantPar {
				t.Errorf("params = %q, want %q", got[0].ParamString(), tt.wantPar)
			}
		})
	}
}

// TestParseRequestsCompatNotification checks that an absent, null or rejected id
// still produces a notification, as the previously vendored library did.
func TestParseRequestsCompatNotification(t *testing.T) {
	for _, msg := range []string{
		`{"jsonrpc":"2.0","method":"GetAddress"}`,
		`{"jsonrpc":"2.0","id":null,"method":"GetAddress"}`,
		`{"jsonrpc":"2.0","id":true,"method":"GetAddress"}`,
	} {
		got, err := parseRequestsCompat([]byte(msg))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", msg, err)
		}
		if len(got) != 1 || got[0] == nil {
			t.Fatalf("%s: expected one request", msg)
		}
		if !got[0].IsNotification() {
			t.Errorf("%s: IsNotification = false, want true", msg)
		}
	}
}
