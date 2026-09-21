package auth

import (
	"fmt"
	"io"
)

// Formatting authentication values must not accidentally reveal credentials.
// JSON encoding is intentionally unchanged for the compatible on-disk format.
func (Credential) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.Credential([REDACTED])")
}
func (InstanceTokenCredential) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.InstanceTokenCredential([REDACTED])")
}
func (AuthTransaction) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.AuthTransaction([REDACTED])")
}
func (PollResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "auth.PollResult([REDACTED])")
}
func (Config) Format(f fmt.State, _ rune)  { _, _ = io.WriteString(f, "auth.Config([REDACTED])") }
func (*Client) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "auth.Client([REDACTED])") }
