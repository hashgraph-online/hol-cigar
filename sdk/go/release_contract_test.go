package cigar

import (
	"encoding/json"
	"os"
	"testing"

	contextv1 "github.com/CIGAR/cigar/sdk/go/gen/contextv1"
)

func TestReleaseMetadataAndDescriptorBindContextABI(t *testing.T) {
	releaseBytes, err := os.ReadFile("release.json")
	if err != nil {
		t.Fatal(err)
	}
	var release struct {
		SchemaVersion string `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		ContextABI    string `json:"context_abi"`
	}
	if err := json.Unmarshal(releaseBytes, &release); err != nil {
		t.Fatal(err)
	}
	if release.SchemaVersion != "cigar.sdk-release.v1" ||
		release.Name != "github.com/CIGAR/cigar/sdk/go" ||
		release.Version != "0.1.0" ||
		release.ContextABI != ContextABI ||
		string(contextv1.File_context_abi_proto.Package()) != ContextABI {
		t.Fatalf("release binding differs: %+v descriptor=%q", release, contextv1.File_context_abi_proto.Package())
	}
}
