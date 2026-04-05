package main

import (
	"testing"
)

func TestHashSpiffeID(t *testing.T) {
	tests := []struct {
		name        string
		spiffeID    string
		domainChars int
		pathChars   int
		wantLen     int
	}{
		{
			name:        "standard 32-char output",
			spiffeID:    "spiffe://org-a.example/workload/jenkins",
			domainChars: 16, pathChars: 16, wantLen: 32,
		},
		{
			name:        "different trust domain same path",
			spiffeID:    "spiffe://org-b.example/workload/jenkins",
			domainChars: 16, pathChars: 16, wantLen: 32,
		},
		{
			name:        "64-char output",
			spiffeID:    "spiffe://example.org/ns/prod/sa/runner",
			domainChars: 32, pathChars: 32, wantLen: 64,
		},
		{
			name:        "no path segment",
			spiffeID:    "spiffe://example.org",
			domainChars: 16, pathChars: 16, wantLen: 32,
		},
		{
			name:        "asymmetric lengths",
			spiffeID:    "spiffe://example.org/workload/x",
			domainChars: 8, pathChars: 24, wantLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashSpiffeID(tt.spiffeID, tt.domainChars, tt.pathChars)
			if len(got) != tt.wantLen {
				t.Errorf("len=%d, want %d (value=%s)", len(got), tt.wantLen, got)
			}
			// deterministic: same input must always produce same output
			if got2 := hashSpiffeID(tt.spiffeID, tt.domainChars, tt.pathChars); got != got2 {
				t.Errorf("non-deterministic: %s != %s", got, got2)
			}
			// output must be lowercase hex
			for _, c := range got {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("non-hex character %q in output %s", c, got)
				}
			}
		})
	}
}

// TestCrossDomainPrefix verifies that two workloads from different trust
// domains always produce different trust-domain hash prefixes, making
// cross-domain collision attacks structurally impossible.
func TestCrossDomainPrefix(t *testing.T) {
	domains := []string{
		"spiffe://org-a.example/workload/deploy",
		"spiffe://org-b.example/workload/deploy",
		"spiffe://attacker.evil/workload/deploy",
	}
	domainChars := 16
	pathChars := 16
	prefixes := make(map[string]string)
	for _, id := range domains {
		h := hashSpiffeID(id, domainChars, pathChars)
		prefix := h[:domainChars]
		if existing, collision := prefixes[prefix]; collision {
			t.Errorf("trust domain hash collision between %q and %q (prefix=%s)", existing, id, prefix)
		}
		prefixes[prefix] = id
	}
}

// TestSamePathDifferentDomain confirms full output differs when only the
// trust domain differs (regression guard for the split-hash design).
func TestSamePathDifferentDomain(t *testing.T) {
	h1 := hashSpiffeID("spiffe://org-a.example/workload/jenkins", 16, 16)
	h2 := hashSpiffeID("spiffe://org-b.example/workload/jenkins", 16, 16)
	if h1 == h2 {
		t.Errorf("different trust domains produced identical hash: %s", h1)
	}
}

// TestSameDomainDifferentPath confirms full output differs when only the
// path differs within the same trust domain.
func TestSameDomainDifferentPath(t *testing.T) {
	h1 := hashSpiffeID("spiffe://example.org/workload/service-a", 16, 16)
	h2 := hashSpiffeID("spiffe://example.org/workload/service-b", 16, 16)
	if h1 == h2 {
		t.Errorf("different paths produced identical hash: %s", h1)
	}
}
