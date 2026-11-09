package function

import (
	"context"
	"fmt"
	"net/http"

	"github.com/tianacloud/sdk-go/internal/functioncontext"
)

// ContextFromRequest preserves cancellation and the incoming request's diagnostic
// identity for supervisor calls, including GetContext and file operations.
// It copies the header values, without retaining r.
func ContextFromRequest(r *http.Request) context.Context {
	return functioncontext.FromRequest(r)
}

// RequestError identifies a failed supervisor secret request. Status is zero
// when no HTTP response was received. Unwrap preserves ErrNotExist and cancellation.
type RequestError struct {
	RequestID string
	Status    int
	cause     error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%v (request_id=%s)", e.cause, e.RequestID)
}
func (e *RequestError) Unwrap() error { return e.cause }
