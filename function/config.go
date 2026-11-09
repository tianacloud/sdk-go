// Package function provides helpers for Go programs running in Tiana Functions.
package function

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/tianacloud/sdk-go/internal/functioncontext"
)

// ErrNotExist means the parameter or its referenced secret does not exist.
var ErrNotExist = errors.New("function: parameter or secret does not exist")

// Parameter is a plain value or a key in the user's secrets store.
type Parameter struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Config owns its typed definitions. Secret values are fetched only by Get.
type Config map[string]Parameter

var configCache struct {
	sync.Mutex
	path   string
	values Config
}

// Get returns a plain value locally, or resolves a configured secret through
// the execution supervisor. An existing empty value returns ("", nil).
func (c Config) Get(key string) (string, error) {
	return c.GetContext(context.Background(), key)
}

// GetContext resolves a parameter with caller cancellation. Use ContextFromRequest
// to associate a secret lookup with an incoming HTTP request.
func (c Config) GetContext(ctx context.Context, key string) (string, error) {
	p, ok := c[key]
	if !ok {
		return "", ErrNotExist
	}
	switch p.Kind {
	case "plain":
		return p.Value, nil
	case "secret":
		identity := functioncontext.FromContext(ctx)
		if identity.RequestID == "" {
			identity.RequestID = rand.Text()
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://supervisor.tiana.com:80/get_secret?key="+url.QueryEscape(key), nil)
		if err != nil {
			return "", &RequestError{RequestID: identity.RequestID, cause: errors.New("function: secret request failed")}
		}
		request.Header.Set("x-request-id", identity.RequestID)
		if identity.Traceparent != "" {
			request.Header.Set("traceparent", identity.Traceparent)
		}
		response, err := jobClient.Do(request)
		if err != nil {
			return "", &RequestError{RequestID: identity.RequestID, cause: errors.Join(errors.New("function: secret request failed"), ctx.Err())}
		}
		defer response.Body.Close()
		if id := response.Header.Get("x-request-id"); id != "" {
			identity.RequestID = id
		}
		failure := func(cause error) (string, error) {
			return "", &RequestError{RequestID: identity.RequestID, Status: response.StatusCode, cause: cause}
		}
		if response.StatusCode == http.StatusNotFound {
			return failure(ErrNotExist)
		}
		if response.StatusCode != http.StatusOK {
			return failure(fmt.Errorf("function: secret request returned HTTP %d", response.StatusCode))
		}
		var result struct {
			Value *string `json:"value"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 8*1024*1024)).Decode(&result) != nil || result.Value == nil {
			return failure(errors.Join(errors.New("function: invalid secret response"), ctx.Err()))
		}
		return *result.Value, nil
	default:
		return "", errors.New("function: unsupported parameter kind")
	}
}

// ReadConfig reads FUNCTION_CONFIG_FILE without resolving secret references.
// An incomplete in-place file update retains this file's last successful read.
// Callers own the returned map. Semantic errors are returned directly.
func ReadConfig() (Config, error) {
	configCache.Lock()
	defer configCache.Unlock()
	path := os.Getenv("FUNCTION_CONFIG_FILE")
	if path != configCache.path {
		configCache.path = path
		configCache.values = nil
	}
	if path == "" {
		return nil, errors.New("function: FUNCTION_CONFIG_FILE is not set")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		var fields Config
		if json.Unmarshal(data, &fields) == nil {
			for _, field := range fields {
				if field.Kind != "plain" && field.Kind != "secret" {
					return nil, errors.New("function: unsupported parameter kind")
				}
			}
			if fields == nil {
				fields = Config{}
			}
			configCache.values = fields
		}
	}
	if configCache.values != nil {
		return maps.Clone(configCache.values), nil
	}
	return nil, errors.New("function: cannot read parameter configuration")
}
