package tiana

import (
	"strings"
	"testing"
)

// Rejecting bare IDs prevents accidental connections to an implicit deployment.
func TestEndpointRequiresDeploymentHostname(t *testing.T) {
	for _, value := range []string{testEndpoint, "", testEndpoint + ".", testEndpoint + ".db..example.com", testEndpoint + ".db.example.com:443", "https://" + testEndpoint + ".db.example.com"} {
		if _, err := ParseEndpoint(value); err == nil {
			t.Errorf("accepted invalid Endpoint %q", value)
		}
	}
}

func TestEndpointDNSLimits(t *testing.T) {
	cases := []struct {
		name, value string
		valid       bool
	}{
		{"label63", testEndpoint + "." + strings.Repeat("a", 63) + ".example", true},
		{"label64", testEndpoint + "." + strings.Repeat("a", 64) + ".example", false},
		{"host253", testEndpoint + "." + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 31), true},
		{"host254", testEndpoint + "." + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 32), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEndpoint(tc.value)
			if (err == nil) != tc.valid {
				t.Errorf("hostname length %d: err=%v", len(tc.value), err)
			}
		})
	}
}
