// Command cigar-qualify-bundle prints the verified shared SDK bundle identity.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/CIGAR/cigar/sdk/go"
)

func main() {
	path := "fixtures/semantic-bundle-v1.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	source, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var fixture struct {
		SchemaVersion    string          `json:"schema_version"`
		Bundle           json.RawMessage `json:"bundle"`
		ExpectedBundleID string          `json:"expected_bundle_id"`
	}
	if err := json.Unmarshal(source, &fixture); err != nil {
		log.Fatal(err)
	}
	if fixture.SchemaVersion != "cigar.sdk-semantic-bundle-fixture.v1" {
		log.Fatal("unsupported semantic bundle fixture")
	}
	id, err := cigar.VerifyBundleJSON(fixture.Bundle)
	if err != nil {
		log.Fatal(err)
	}
	if id != fixture.ExpectedBundleID {
		log.Fatal("shared semantic bundle identity differs")
	}
	fmt.Println(id)
}
