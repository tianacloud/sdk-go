package auth

import (
	"context"
	"errors"
	"net/http"
)

// DoJSON sends an authenticated request to this client's configured MGR origin.
// It refreshes credentials and repeats the request once only on HTTP 401.
// Mutating callers must supply a stable Idempotency-Key and immutable payload.
// Other failures, including unknown outcomes, are returned without replay.
// It does not initiate browser login; use RunAuthenticated or Login explicitly.
func (c *Client) DoJSON(ctx context.Context, method, path string, payload any, headers map[string]string, result any) (int, error) {
	return c.authorized(ctx, func(ctx context.Context, accessToken string) (int, error) {
		return c.doJSONWithHeadersStatus(ctx, method, path, payload, accessToken, headers, result)
	})
}

// authorized runs one request with a usable session and refreshes it once on
// a session rejection. A second rejection is reported as
// ErrAuthenticationRequired so the caller can start browser authentication.
func (c *Client) authorized(ctx context.Context, run func(context.Context, string) (int, error)) (int, error) {
	credential, err := c.EnsureCredential(ctx)
	if err != nil {
		return 0, err
	}
	status, err := run(ctx, credential.AccessToken)
	if err == nil {
		return status, nil
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		return status, err
	}
	credential, err = c.refresh(ctx, credential)
	if err != nil {
		return 0, err
	}
	status, err = run(ctx, credential.AccessToken)
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		return status, ErrAuthenticationRequired
	}
	return status, err
}
