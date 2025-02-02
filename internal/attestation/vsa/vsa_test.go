package vsa

import (
	"fmt"
	"testing"
)

const testVSA = `{
	"_type": "https://in-toto.io/Statement/v1",
	"subject": [{
		"name": "test-artifact",
		"digest": {"sha256": "abc123"}
	}],
	"predicateType": "https://slsa.dev/verification_summary/v1",
	"predicate": {
		"verifier": {
			"id": "test-verifier"
		},
		"timeVerified": "2024-01-01T00:00:00Z",
		"resourceUri": "test://artifact",
		"verificationResult": "PASSED",
		"verifiedLevels": ["SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_2"],
		"slsaVersion": "1.0"
	}
}`

func TestNewVSAFromBytes(t *testing.T) {
	vsa, err := NewVSAFromBytes([]byte(testVSA))
	if err != nil {
		t.Fatalf("Failed to parse VSA: %v", err)
	}

	if vsa.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Expected type %s, got %s", "https://in-toto.io/Statement/v1", vsa.Type)
	}

	if vsa.PredicateType != "https://slsa.dev/verification_summary/v1" {
		t.Errorf("Expected predicate type %s, got %s", "https://slsa.dev/verification_summary/v1", vsa.PredicateType)
	}
}

func TestGetBuildLevel(t *testing.T) {
	vsa, err := NewVSAFromBytes([]byte(testVSA))
	if err != nil {
		t.Fatalf("Failed to parse VSA: %v", err)
	}

	level, err := vsa.GetBuildLevel()
	if err != nil {
		t.Fatalf("Failed to get build level: %v", err)
	}

	if level != 3 {
		t.Errorf("Expected build level 3, got %d", level)
	}
}

func TestVerifyBuildLevel(t *testing.T) {
	vsa, err := NewVSAFromBytes([]byte(testVSA))
	if err != nil {
		t.Fatalf("Failed to parse VSA: %v", err)
	}

	// pass for lvl 3 or lower
	if err := vsa.VerifyBuildLevel(3); err != nil {
		t.Errorf("Expected level 3 to pass: %v", err)
	}

	// invalid levels per SLSA v1.0 spec
	invalidLevels := []int{-1, 4, 5, 10}
	for _, level := range invalidLevels {
		err := vsa.VerifyBuildLevel(level)
		if err == nil {
			t.Errorf("Expected level L%d to fail - SLSA v1.0 only defines build levels L0-L3", level)
		}
		if err != nil && err.Error() != fmt.Sprintf("invalid SLSA build level %d: SLSA v1.0 only defines build levels L0-L3", level) {
			t.Errorf("Unexpected error message for level L%d: %v", level, err)
		}
	}

	// valid SLSA v1.0 build levels
	validLevels := []int{0, 1, 2, 3}
	for _, level := range validLevels {
		if err := vsa.VerifyBuildLevel(level); err != nil {
			t.Errorf("Expected build level L%d to pass: %v", level, err)
		}
	}
}

func TestValidateVerifier(t *testing.T) {
	vsa, err := NewVSAFromBytes([]byte(testVSA))
	if err != nil {
		t.Fatalf("Failed to parse VSA: %v", err)
	}

	// pass for trusted verifier
	trusted := []string{"test-verifier"}
	if err := vsa.ValidateVerifier(trusted); err != nil {
		t.Errorf("Expected trusted verifier to pass: %v", err)
	}

	// fail for untrusted verifier
	untrusted := []string{"other-verifier"}
	if err := vsa.ValidateVerifier(untrusted); err == nil {
		t.Error("Expected untrusted verifier to fail")
	}
}
