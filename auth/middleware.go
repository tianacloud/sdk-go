package auth

import (
	"context"
	"errors"
	"fmt"
)

// AuthenticatedOperation is a control-plane operation that runs with one
// usable CLI credential. The operation receives the credential selected for
// this invocation so it can pass it to its request layer or record its stable
// account ID in a local resume intent.
type AuthenticatedOperation func(context.Context, Credential) error

// RunAuthenticated obtains or refreshes a CLI credential, starting browser
// authentication when the local credential is absent or revoked, and invokes
// operation once. A failed operation is returned to its caller; in
// particular, this helper does not retry mutations whose result is unknown.
func (c *Client) RunAuthenticated(ctx context.Context, operation AuthenticatedOperation) error {
	if c == nil {
		return errors.New("auth client is not configured")
	}
	if operation == nil {
		return errors.New("authenticated operation is required")
	}
	credential, err := c.EnsureCredential(ctx)
	if errors.Is(err, ErrAuthenticationRequired) && !c.nonInteractive {
		fmt.Fprintln(c.output, "You need to authenticate.")
		credential, err = c.Login(ctx)
	}
	if err != nil {
		return err
	}
	return operation(ctx, credential)
}
