// Command cigar-verify-replay independently verifies the CIGAR replay reproduction vector.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

const (
	maxFixtureBytes         = 1_048_576
	maxRetainedBytes        = 1_048_576
	maxEncodedRetainedBytes = 1_398_104
	maxArtifacts            = 64
	maxObservations         = 1_024
	maxJSONDepth            = 64
)

var dependencyOrder = []string{
	"source", "blob", "policy", "index", "manifest", "bundle", "tokenizer", "adapter", "consumer", "tool_schema", "environment",
}

type retainedFixture struct {
	BundleBytesBase64URL              string   `json:"bundle_bytes_base64url"`
	InvocationBytesBase64URL          string   `json:"invocation_bytes_base64url"`
	RecordedObservationBytesBase64URL []string `json:"recorded_observation_bytes_base64url"`
}

type retainedArtifact struct {
	Kind            string `json:"kind"`
	BytesBase64URL  string `json:"bytes_base64url"`
	DigestMultihash string `json:"digest_multihash"`
}

type missingArtifactProbe struct {
	Kind                        string   `json:"kind"`
	ExpectedComplete            *bool    `json:"expected_complete"`
	ExpectedMissingDependencies []string `json:"expected_missing_dependencies"`
}

type tamperedArtifactProbe struct {
	Kind                        string   `json:"kind"`
	ReplacementBytesBase64URL   string   `json:"replacement_bytes_base64url"`
	ExpectedAccepted            *bool    `json:"expected_accepted"`
	ExpectedMissingDependencies []string `json:"expected_missing_dependencies"`
}

type emptyRecordedResponseProbe struct {
	BytesBase64URL   *string `json:"bytes_base64url"`
	DigestMultihash  string  `json:"digest_multihash"`
	ExpectedAccepted *bool   `json:"expected_accepted"`
}

type expectedResult struct {
	BundleDigestMultihash      string   `json:"bundle_digest_multihash"`
	InvocationDigestMultihash  string   `json:"invocation_digest_multihash"`
	ObservationDigestMultihash string   `json:"observation_digest_multihash"`
	Complete                   *bool    `json:"complete"`
	MissingDependencies        []string `json:"missing_dependencies"`
}

type replayFixture struct {
	SchemaVersion              string                     `json:"schema_version"`
	DigestAlgorithm            string                     `json:"digest_algorithm"`
	ObservationFraming         string                     `json:"observation_framing"`
	Retained                   retainedFixture            `json:"retained"`
	RequiredDependencies       []string                   `json:"required_dependencies"`
	RetainedArtifacts          []retainedArtifact         `json:"retained_artifacts"`
	MissingArtifactProbe       missingArtifactProbe       `json:"missing_artifact_probe"`
	TamperedArtifactProbe      tamperedArtifactProbe      `json:"tampered_artifact_probe"`
	EmptyRecordedResponseProbe emptyRecordedResponseProbe `json:"empty_recorded_response_probe"`
	Expected                   expectedResult             `json:"expected"`
}

type completenessProbeOutput struct {
	Complete            bool     `json:"complete"`
	MissingDependencies []string `json:"missing_dependencies"`
}

type tamperProbeOutput struct {
	Accepted            bool     `json:"accepted"`
	MissingDependencies []string `json:"missing_dependencies"`
}

type emptyResponseProbeOutput struct {
	Accepted        bool   `json:"accepted"`
	DigestMultihash string `json:"digest_multihash"`
}

type reproductionOutput struct {
	SchemaVersion              string                   `json:"schema_version"`
	BundleDigestMultihash      string                   `json:"bundle_digest_multihash"`
	InvocationDigestMultihash  string                   `json:"invocation_digest_multihash"`
	ObservationDigestMultihash string                   `json:"observation_digest_multihash"`
	Complete                   bool                     `json:"complete"`
	MissingDependencies        []string                 `json:"missing_dependencies"`
	MissingArtifactProbe       completenessProbeOutput  `json:"missing_artifact_probe"`
	TamperedArtifactProbe      tamperProbeOutput        `json:"tampered_artifact_probe"`
	EmptyRecordedResponseProbe emptyResponseProbeOutput `json:"empty_recorded_response_probe"`
}

type artifactVerification struct {
	verifiedBytes map[string][]byte
	missing       []string
}

func main() {
	path := "schemas/vectors/replay-v1.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	result, err := verify(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay vector verification failed: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay result serialization failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}

func verify(path string) (reproductionOutput, error) {
	var empty reproductionOutput
	source, err := readBounded(path)
	if err != nil {
		return empty, err
	}
	if !utf8.Valid(source) {
		return empty, errors.New("fixture is not valid UTF-8")
	}
	if err := rejectDuplicateKeys(source); err != nil {
		return empty, err
	}
	var fixture replayFixture
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		return empty, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return empty, errors.New("fixture contains trailing JSON")
	}
	if fixture.SchemaVersion != "cigar.replay-vector.v1" || fixture.DigestAlgorithm != "sha256-multihash-raw-v1" || fixture.ObservationFraming != "u32be-length-prefixed-v1" {
		return empty, errors.New("fixture declares an unsupported profile")
	}

	bundle, err := decodeExactBase64URL(fixture.Retained.BundleBytesBase64URL, "bundle", false)
	if err != nil {
		return empty, err
	}
	invocation, err := decodeExactBase64URL(fixture.Retained.InvocationBytesBase64URL, "invocation", false)
	if err != nil {
		return empty, err
	}
	if len(fixture.Retained.RecordedObservationBytesBase64URL) == 0 || len(fixture.Retained.RecordedObservationBytesBase64URL) > maxObservations {
		return empty, errors.New("recorded observations must be non-empty and bounded")
	}
	observations := make([][]byte, 0, len(fixture.Retained.RecordedObservationBytesBase64URL))
	for index, encoded := range fixture.Retained.RecordedObservationBytesBase64URL {
		observation, decodeErr := decodeExactBase64URL(encoded, fmt.Sprintf("recorded observation %d", index), true)
		if decodeErr != nil {
			return empty, decodeErr
		}
		observations = append(observations, observation)
	}

	if !sameStrings(fixture.RequiredDependencies, dependencyOrder) {
		return empty, errors.New("required dependency order differs")
	}
	if err := validateArtifacts(fixture.RequiredDependencies, fixture.RetainedArtifacts); err != nil {
		return empty, err
	}

	for context, digest := range map[string]string{
		"bundle digest":      fixture.Expected.BundleDigestMultihash,
		"invocation digest":  fixture.Expected.InvocationDigestMultihash,
		"observation digest": fixture.Expected.ObservationDigestMultihash,
	} {
		if err := verifyDigest(digest, context); err != nil {
			return empty, err
		}
	}
	bundleDigest := multihash(bundle)
	invocationDigest := multihash(invocation)
	observationDigest, err := observationMultihash(observations)
	if err != nil {
		return empty, err
	}
	if bundleDigest != fixture.Expected.BundleDigestMultihash || invocationDigest != fixture.Expected.InvocationDigestMultihash || observationDigest != fixture.Expected.ObservationDigestMultihash {
		return empty, errors.New("retained replay digest mismatch")
	}

	verification, err := verifyArtifacts(fixture.RequiredDependencies, fixture.RetainedArtifacts)
	if err != nil {
		return empty, err
	}
	complete := len(verification.missing) == 0
	if fixture.Expected.Complete == nil || complete != *fixture.Expected.Complete || fixture.Expected.MissingDependencies == nil || !sameStrings(verification.missing, fixture.Expected.MissingDependencies) {
		return empty, errors.New("artifact-derived replay completeness differs")
	}
	artifactBundle, exists := verification.verifiedBytes["bundle"]
	if !exists || !bytes.Equal(artifactBundle, bundle) {
		return empty, errors.New("retained bundle and bundle dependency artifact differ")
	}

	missingProbe := fixture.MissingArtifactProbe
	if missingProbe.Kind == "" || !contains(fixture.RequiredDependencies, missingProbe.Kind) || missingProbe.ExpectedComplete == nil || missingProbe.ExpectedMissingDependencies == nil {
		return empty, errors.New("missing artifact probe is malformed")
	}
	withoutArtifact := make([]retainedArtifact, 0, len(fixture.RetainedArtifacts))
	for _, artifact := range fixture.RetainedArtifacts {
		if artifact.Kind != missingProbe.Kind {
			withoutArtifact = append(withoutArtifact, artifact)
		}
	}
	missingVerification, err := verifyArtifacts(fixture.RequiredDependencies, withoutArtifact)
	if err != nil {
		return empty, err
	}
	missingComplete := len(missingVerification.missing) == 0
	if missingComplete != *missingProbe.ExpectedComplete || !sameStrings(missingVerification.missing, missingProbe.ExpectedMissingDependencies) {
		return empty, errors.New("missing artifact probe differs")
	}

	tamperProbe := fixture.TamperedArtifactProbe
	if tamperProbe.Kind == "" || !contains(fixture.RequiredDependencies, tamperProbe.Kind) || tamperProbe.ExpectedAccepted == nil || tamperProbe.ExpectedMissingDependencies == nil {
		return empty, errors.New("tampered artifact probe is malformed")
	}
	tampered := append([]retainedArtifact(nil), fixture.RetainedArtifacts...)
	replacements := 0
	for index := range tampered {
		if tampered[index].Kind == tamperProbe.Kind {
			tampered[index].BytesBase64URL = tamperProbe.ReplacementBytesBase64URL
			replacements++
		}
	}
	if replacements != 1 {
		return empty, errors.New("tampered artifact probe must identify exactly one artifact")
	}
	tamperedVerification, err := verifyArtifacts(fixture.RequiredDependencies, tampered)
	if err != nil {
		return empty, err
	}
	tamperAccepted := len(tamperedVerification.missing) == 0
	if tamperAccepted != *tamperProbe.ExpectedAccepted || !sameStrings(tamperedVerification.missing, tamperProbe.ExpectedMissingDependencies) {
		return empty, errors.New("tampered artifact probe differs")
	}

	emptyProbe := fixture.EmptyRecordedResponseProbe
	if emptyProbe.BytesBase64URL == nil || emptyProbe.ExpectedAccepted == nil {
		return empty, errors.New("empty recorded response probe is malformed")
	}
	emptyResponse, err := decodeExactBase64URL(*emptyProbe.BytesBase64URL, "empty recorded response", true)
	if err != nil {
		return empty, err
	}
	if err := verifyDigest(emptyProbe.DigestMultihash, "empty recorded response digest"); err != nil {
		return empty, err
	}
	emptyDigest := multihash(emptyResponse)
	emptyAccepted := len(emptyResponse) == 0 && emptyDigest == emptyProbe.DigestMultihash
	if emptyAccepted != *emptyProbe.ExpectedAccepted {
		return empty, errors.New("empty recorded response probe differs")
	}

	return reproductionOutput{
		SchemaVersion:              "cigar.replay-reproduction-result.v1",
		BundleDigestMultihash:      bundleDigest,
		InvocationDigestMultihash:  invocationDigest,
		ObservationDigestMultihash: observationDigest,
		Complete:                   complete,
		MissingDependencies:        verification.missing,
		MissingArtifactProbe: completenessProbeOutput{
			Complete:            missingComplete,
			MissingDependencies: missingVerification.missing,
		},
		TamperedArtifactProbe: tamperProbeOutput{
			Accepted:            tamperAccepted,
			MissingDependencies: tamperedVerification.missing,
		},
		EmptyRecordedResponseProbe: emptyResponseProbeOutput{
			Accepted:        emptyAccepted,
			DigestMultihash: emptyDigest,
		},
	}, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	source, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if err != nil {
		return nil, err
	}
	if len(source) == 0 || len(source) > maxFixtureBytes {
		return nil, errors.New("fixture size is invalid")
	}
	return source, nil
}

func rejectDuplicateKeys(source []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxJSONDepth {
			return errors.New("fixture JSON nesting exceeds its bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim('}') {
				return errors.New("invalid JSON object closing delimiter")
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim(']') {
				return errors.New("invalid JSON array closing delimiter")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("fixture contains trailing JSON")
	}
	return nil
}

func validateArtifacts(required []string, artifacts []retainedArtifact) error {
	if len(artifacts) > maxArtifacts {
		return errors.New("retained artifact table exceeds its bound")
	}
	seen := make(map[string]struct{}, len(artifacts))
	for index, artifact := range artifacts {
		if artifact.Kind == "" || !contains(required, artifact.Kind) {
			return errors.New("retained artifact kind is malformed or unknown")
		}
		if _, exists := seen[artifact.Kind]; exists {
			return errors.New("retained artifact kind is duplicated")
		}
		seen[artifact.Kind] = struct{}{}
		if artifact.BytesBase64URL == "" {
			return errors.New("retained artifact bytes must not be empty")
		}
		if err := verifyDigest(artifact.DigestMultihash, fmt.Sprintf("retained artifact %d digest", index)); err != nil {
			return err
		}
	}
	return nil
}

func verifyArtifacts(required []string, artifacts []retainedArtifact) (artifactVerification, error) {
	verified := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		content, err := decodeExactBase64URL(artifact.BytesBase64URL, artifact.Kind+" artifact", false)
		if err != nil {
			return artifactVerification{}, err
		}
		if multihash(content) == artifact.DigestMultihash {
			verified[artifact.Kind] = content
		}
	}
	missing := make([]string, 0)
	for _, kind := range required {
		if _, exists := verified[kind]; !exists {
			missing = append(missing, kind)
		}
	}
	return artifactVerification{verifiedBytes: verified, missing: missing}, nil
}

func decodeExactBase64URL(value string, context string, allowEmpty bool) ([]byte, error) {
	if value == "" {
		if allowEmpty {
			return []byte{}, nil
		}
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	if len(value) > maxEncodedRetainedBytes {
		return nil, fmt.Errorf("%s exceeds its encoded bound", context)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maxRetainedBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is invalid, non-canonical, or unbounded base64url", context)
	}
	return decoded, nil
}

func multihash(value []byte) string {
	digest := sha256.Sum256(value)
	return "1220" + hex.EncodeToString(digest[:])
}

func observationMultihash(observations [][]byte) (string, error) {
	digest := sha256.New()
	var frame [4]byte
	for _, observation := range observations {
		if uint64(len(observation)) > uint64(^uint32(0)) {
			return "", errors.New("recorded observation exceeds u32 framing")
		}
		binary.BigEndian.PutUint32(frame[:], uint32(len(observation)))
		if _, err := digest.Write(frame[:]); err != nil {
			return "", err
		}
		if _, err := digest.Write(observation); err != nil {
			return "", err
		}
	}
	return "1220" + hex.EncodeToString(digest.Sum(nil)), nil
}

func verifyDigest(value string, context string) error {
	if len(value) != 68 || value[:4] != "1220" {
		return fmt.Errorf("%s is not a lowercase SHA-256 multihash", context)
	}
	decoded, err := hex.DecodeString(value[4:])
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value[4:] {
		return fmt.Errorf("%s is not a lowercase SHA-256 multihash", context)
	}
	return nil
}

func sameStrings(first []string, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index, value := range first {
		if value != second[index] {
			return false
		}
	}
	return true
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
