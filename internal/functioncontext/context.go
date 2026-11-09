// Package functioncontext carries request diagnostics between Function helpers.
package functioncontext

import (
	"context"
	"net/http"
)

type key struct{}
type Identity struct{ RequestID, Traceparent string }

func FromRequest(r *http.Request) context.Context {
	return context.WithValue(r.Context(), key{}, Identity{r.Header.Get("x-request-id"), r.Header.Get("traceparent")})
}
func FromContext(ctx context.Context) Identity { value, _ := ctx.Value(key{}).(Identity); return value }
