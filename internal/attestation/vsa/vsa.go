package vsa

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// VSA represents a Verification Summary Attestation.
// these are created by verifier tools (like slsa-verifier) that check slsa compliance,
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
		TimeVerified       string         `json:"timeVerified"`
		ResourceURI        string         `json:"resourceUri"`
		VerificationResult string         `json:"verificationResult"`
		VerifiedLevels     []string       `json:"verifiedLevels"`
		DependencyLevels   map[string]int `json:"dependencyLevels,omitempty"`
		SlsaVersion        string         `json:"slsaVersion,omitempty"`
	} `json:"predicate"`
}

// returns the highest slsa build level from a vsa's verifiedLevels
func (v *VSA) GetBuildLevel() (int, error) {
	// consider lvls if verification passed
	if v.Predicate.VerificationResult != "PASSED" {
		return -1, fmt.Errorf("VSA verification result is not PASSED")
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

	return nil
}

// parses a vsa from json bytes
func NewVSAFromBytes(data []byte) (*VSA, error) {
	var vsa VSA
	if err := json.Unmarshal(data, &vsa); err != nil {
		return nil, err
	}
	return &vsa, nil
}
