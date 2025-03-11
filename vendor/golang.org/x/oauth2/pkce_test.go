package oauth2

import (
    "crypto/sha256"
    "encoding/base64"
    "net/url"
    "crypto/rand"
    "errors"
    "testing"
)
// errorReader implements io.Reader and always returns an error to simulate a failure in rand.Read.
type errorReader struct{}
func (er errorReader) Read(p []byte) (int, error) {
    return 0, errors.New("injected error")
}

// TestGenerateVerifier tests that GenerateVerifier produces a valid, 43-octet URL safe string.
func TestGenerateVerifier(t *testing.T) {
    verifier := GenerateVerifier()
    // Check that it is a 43 character string.
    if len(verifier) != 43 {
        t.Errorf("expected verifier length 43, got %d", len(verifier))
    }
    // Check that the verifier decodes correctly as base64 URL encoding.
    if _, err := base64.RawURLEncoding.DecodeString(verifier); err != nil {
        t.Errorf("failed to decode verifier: %v", err)
    }
}

// TestVerifierOption tests that VerifierOption sets the "code_verifier" parameter correctly.
func TestVerifierOption(t *testing.T) {
    verifier := "testVerifier"
    option := VerifierOption(verifier)
    values := url.Values{}
    // The option should satisfy an interface with setValue(url.Values).
    setter, ok := option.(interface{ setValue(url.Values) })
    if !ok {
        t.Fatalf("VerifierOption does not implement setValue")
    }
    setter.setValue(values)
    if got := values.Get("code_verifier"); got != verifier {
        t.Errorf("expected code_verifier %q, got %q", verifier, got)
    }
}

// TestS256ChallengeFromVerifier tests that S256ChallengeFromVerifier produces
// the correct SHA-256 based code challenge.
func TestS256ChallengeFromVerifier(t *testing.T) {
    verifier := "testVerifier"
    challenge := S256ChallengeFromVerifier(verifier)
    shaSum := sha256.Sum256([]byte(verifier))
    expected := base64.RawURLEncoding.EncodeToString(shaSum[:])
    if challenge != expected {
        t.Errorf("expected challenge %q, got %q", expected, challenge)
    }
}

// TestS256ChallengeOption tests that S256ChallengeOption sets both the code_challenge
// and code_challenge_method parameters correctly in the URL values.
func TestS256ChallengeOption(t *testing.T) {
    verifier := "testVerifier"
    option := S256ChallengeOption(verifier)
    values := url.Values{}
    setter, ok := option.(interface{ setValue(url.Values) })
    if !ok {
        t.Fatalf("S256ChallengeOption does not implement setValue")
    }
    setter.setValue(values)
    expectedChallenge := S256ChallengeFromVerifier(verifier)
    if method := values.Get("code_challenge_method"); method != "S256" {
        t.Errorf("expected challenge_method S256, got %q", method)
    }
    if challenge := values.Get("code_challenge"); challenge != expectedChallenge {
        t.Errorf("expected challenge %q, got %q", expectedChallenge, challenge)
    }
}
// TestGenerateVerifierPanic tests that GenerateVerifier panics when rand.Read fails.
func TestGenerateVerifierPanic(t *testing.T) {
    // Preserve the original rand.Reader.
    originalReader := rand.Reader
    defer func() { rand.Reader = originalReader }()

    // Override rand.Reader with errorReader to simulate an error.
    rand.Reader = errorReader{}

    // Expecting a panic.
    defer func() {
        if r := recover(); r == nil {
            t.Errorf("expected panic when rand.Read fails, but no panic occurred")
        }
    }()
    _ = GenerateVerifier()
}

// TestS256ChallengeEmptyVerifier tests that S256ChallengeFromVerifier works correctly even for an empty verifier.
func TestS256ChallengeEmptyVerifier(t *testing.T) {
    verifier := ""
    challenge := S256ChallengeFromVerifier(verifier)
    sum := sha256.Sum256([]byte(verifier))
    expected := base64.RawURLEncoding.EncodeToString(sum[:])
    if challenge != expected {
        t.Errorf("expected challenge %q for empty verifier, got %q", expected, challenge)
    }
}

// TestChallengeOptionSetValue tests that challengeOption.setValue sets the URL parameters correctly.
func TestChallengeOptionSetValue(t *testing.T) {
    // Manually create a challengeOption instance.
    opt := challengeOption{challenge_method: "S256", challenge: "dummy_challenge"}
    values := url.Values{}
    opt.setValue(values)
    if got := values.Get(codeChallengeMethodKey); got != "S256" {
        t.Errorf("expected code_challenge_method 'S256', got %q", got)
    }
    if got := values.Get(codeChallengeKey); got != "dummy_challenge" {
        t.Errorf("expected code_challenge 'dummy_challenge', got %q", got)
    }
}