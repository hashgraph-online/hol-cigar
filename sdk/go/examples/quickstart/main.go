// Command quickstart verifies the shared bundle identity and optionally negotiates over gRPC.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/CIGAR/cigar/sdk/go"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const expectedBundleID = "1220d7af77d795d93d836e493e18a574f87daa7b8c40561ce6349bd3d4aa01dedb84"

func main() {
	path := os.Getenv("CIGAR_FIXTURE")
	if path == "" {
		path = "fixtures/semantic-bundle-v1.json"
	}
	source, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var fixture struct {
		Bundle           json.RawMessage `json:"bundle"`
		ExpectedBundleID string          `json:"expected_bundle_id"`
	}
	if err := json.Unmarshal(source, &fixture); err != nil {
		log.Fatal(err)
	}
	identity, err := cigar.VerifyBundleJSON(fixture.Bundle)
	if err != nil || identity != fixture.ExpectedBundleID || identity != expectedBundleID {
		log.Fatalf("shared semantic bundle identity differs: identity=%s error=%v", identity, err)
	}

	if target := os.Getenv("CIGAR_GRPC_TARGET"); target != "" {
		transport := credentials.TransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13}))
		if os.Getenv("CIGAR_GRPC_INSECURE_LOOPBACK") == "1" {
			if !loopbackTarget(target) {
				log.Fatal("insecure gRPC is restricted to an explicit loopback target")
			}
			transport = insecure.NewCredentials()
		}
		client, err := cigar.DialGRPCClient(cigar.GRPCDialOptions{
			Target: target, TransportCredentials: transport,
			BearerToken: os.Getenv("CIGAR_TOKEN"), DefaultTimeout: 5 * time.Second,
		})
		if err != nil {
			log.Fatal(err)
		}
		defer client.Close()
		if _, err := client.Negotiate(context.Background()); err != nil {
			log.Fatal(err)
		}
		planID := os.Getenv("CIGAR_PLAN_ID")
		if planID == "" {
			log.Fatal("CIGAR_PLAN_ID is required with CIGAR_GRPC_TARGET")
		}
		compiled, err := client.CompileContextBundle(
			context.Background(),
			cigar.CompileContextBundleRequest{PlanID: planID},
			cigar.WithInvocationIdempotencyKey("quickstart"),
		)
		if err != nil {
			log.Fatal(err)
		}
		compiledJSON, err := json.Marshal(compiled.Payload())
		if err != nil {
			log.Fatal(err)
		}
		compiledID, err := cigar.VerifyBundleJSON(compiledJSON)
		if err != nil || compiledID != identity {
			log.Fatalf("daemon bundle identity differs from the shared fixture: identity=%s error=%v", compiledID, err)
		}
		manifest, err := client.GetContextBundleManifest(
			context.Background(),
			cigar.BundleIdRequest{BundleID: compiledID},
		)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("verified daemon manifest %s", manifest.Payload().ManifestID)
	}
	fmt.Println(identity)
}

func loopbackTarget(target string) bool {
	normalized := strings.TrimPrefix(strings.TrimPrefix(target, "dns:///"), "passthrough:///")
	return strings.HasPrefix(normalized, "localhost:") || strings.HasPrefix(normalized, "127.0.0.1:") ||
		strings.HasPrefix(normalized, "[::1]:")
}
