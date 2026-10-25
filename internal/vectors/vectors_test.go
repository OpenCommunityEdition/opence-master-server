package vectors

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const path = "../../testdata/vectors.json"

// The checked-in vectors are what the code makes now: a change to either
// is a change to the protocol.
func TestVectorsFile(t *testing.T) {
	made, err := json.MarshalIndent(Generate(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	made = append(made, '\n')
	if *update {
		if err := os.WriteFile(path, made, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/vectors -update)", err)
	}
	if !bytes.Equal(stored, made) {
		t.Fatal("testdata/vectors.json differs from what the code makes (run go test ./internal/vectors -update)")
	}
}
