package auth

import "context"

type requestIdentityKey struct{}

// WithRequestID associates management requests with an existing logical request.
// Calls without an inherited identity generate their own ID before network I/O.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIdentityKey{}, requestID)
}
