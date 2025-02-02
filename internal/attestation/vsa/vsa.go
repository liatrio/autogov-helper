package vsa

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gh-attest-util/internal/template"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// VSA represents a Verification Summary Attestation.
// These are created by verifier tools (like slsa-verifier) that check SLSA compliance,
// not by signing tools like cosign which only handle attestation signatures.
type VSA struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Verifier struct {
			ID string `json:"id"`
		} `json:"verifier"`
		TimeVerified            string `json:"timeVerified"`
		ResourceURI             string `json:"resourceUri"`
		PolicyEvaluationResults []struct {
			Type   string `json:"type"`
			Result string `json:"result"`
		} `json:"policyEvaluationResults"`
		VerifiedLevels   []string       `json:"verifiedLevels"`
		DependencyLevels map[string]int `json:"dependencyLevels,omitempty"`
		SlsaVersion      string         `json:"slsaVersion"`
	} `json:"predicate"`
}

// returns the highest slsa build level from a vsa's verifiedLevels
func (v *VSA) GetBuildLevel() (int, error) {
	// consider lvls if policy evaluation passed
	foundPassedPolicy := false
	for _, result := range v.Predicate.PolicyEvaluationResults {
		if result.Type == "https://slsa.dev/policy/v1" && result.Result == "PASSED" {
			foundPassedPolicy = true
			break
		}
	}
	if !foundPassedPolicy {
		return -1, fmt.Errorf("VSA policy evaluation did not pass")
	}

	maxLevel := -1
	for _, level := range v.Predicate.VerifiedLevels {
		if strings.HasPrefix(level, "SLSA_BUILD_LEVEL_") {
			levelStr := strings.TrimPrefix(level, "SLSA_BUILD_LEVEL_")
			levelNum, err := strconv.Atoi(levelStr)
			if err != nil {
				return -1, err
			}
			if levelNum > maxLevel {
				maxLevel = levelNum
			}
		}
	}
	if maxLevel == -1 {
		return -1, fmt.Errorf("no SLSA build level found in VSA")
	}
	return maxLevel, nil
}

// checks if the vsa was created by a trusted verifier
func (v *VSA) ValidateVerifier(trustedVerifiers []string) error {
	if v.Predicate.Verifier.ID == "" {
		return fmt.Errorf("VSA missing verifier ID")
	}

	for _, trusted := range trustedVerifiers {
		if v.Predicate.Verifier.ID == trusted {
			return nil
		}
	}
	return fmt.Errorf("VSA verifier %s not in trusted list", v.Predicate.Verifier.ID)
}

// verifies the slsa build level using slsa-verifier
func (v *VSA) VerifyBuildLevel(expectedLevel int) error {
	// verify statement format using slsa-verifier utils
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal VSA: %w", err)
	}

	// validate using slsa-verifier's statement verification
	statement, err := utils.StatementFromBytes(payload)
	if err != nil {
		return fmt.Errorf("invalid VSA format: %w", err)
	}

	// verify expected type and predicate type
	if statement.Type != "https://in-toto.io/Statement/v1" {
		return fmt.Errorf("invalid statement type: %s", statement.Type)
	}
	if statement.PredicateType != "https://slsa.dev/verification_summary/v1" {
		return fmt.Errorf("invalid predicate type: %s", statement.PredicateType)
	}

	// validate expected level is within SLSA v1.0 spec
	if expectedLevel < 0 || expectedLevel > 3 {
		return fmt.Errorf("invalid SLSA build level %d: SLSA v1.0 only defines build levels L0-L3", expectedLevel)
	}

	// check build level
	level, err := v.GetBuildLevel()
	if err != nil {
		return fmt.Errorf("failed to get build level: %w", err)
	}

	if level < expectedLevel {
		return fmt.Errorf("VSA build level L%d is lower than expected level L%d", level, expectedLevel)
	}

	// Verify policy evaluation results
	if len(v.Predicate.PolicyEvaluationResults) == 0 {
		return fmt.Errorf("VSA missing policy evaluation results")
	}

	foundSLSAPolicy := false
	for _, result := range v.Predicate.PolicyEvaluationResults {
		if result.Type == "https://slsa.dev/policy/v1" {
			foundSLSAPolicy = true
			if result.Result != "PASSED" {
				return fmt.Errorf("SLSA policy evaluation failed with result: %s", result.Result)
			}
		}
	}

	if !foundSLSAPolicy {
		return fmt.Errorf("VSA missing SLSA policy evaluation result")
	}

	return nil
}

// defines parameters for generating a new VSA
type Options struct {
	SubjectName   string
	SubjectDigest string
	VerifierID    string
	Result        string // PASSED/FAILED
	Levels        []string
	ResourceURI   string
	SlsaVersion   string
	TimeVerified  time.Time
}

// creates a new VSA from generation options
func New(opts Options) (*VSA, error) {
	data := template.VSATemplateData{
		SubjectName:        opts.SubjectName,
		DigestAlgorithm:    "sha256",
		Digest:             strings.TrimPrefix(opts.SubjectDigest, "sha256:"),
		VerifierID:         opts.VerifierID,
		TimeVerified:       opts.TimeVerified.Format(time.RFC3339),
		ResourceURI:        opts.ResourceURI,
		VerificationResult: opts.Result,
		VerifiedLevels:     opts.Levels,
	}

	vsaBytes, err := template.RenderTemplate("vsa", data)
	if err != nil {
		return nil, fmt.Errorf("failed to render VSA template: %w", err)
	}

	return NewVSAFromBytes(vsaBytes)
}

// parses a vsa from json bytes
func NewVSAFromBytes(data []byte) (*VSA, error) {
	var vsa VSA
	if err := json.Unmarshal(data, &vsa); err != nil {
		return nil, err
	}
	return &vsa, nil
}
