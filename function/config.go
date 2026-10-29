// Package function provides helpers for Go programs running in Tiana Functions.
package function

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"sync"
)

var configCache struct {
	sync.Mutex
	path   string
	values map[string]string
}

// Config contains the parameters read from the function's configuration file.
type Config map[string]string

// Get returns a parameter and whether it exists. An empty value can be present.
func (c Config) Get(key string) (string, bool) {
	value, ok := c[key]
	return value, ok
}

// ReadConfig reads the parameter file named by FUNCTION_CONFIG_FILE.
// Each successful read refreshes the process-local cache. If a read fails while
// the platform is updating the file in place, it returns the last successful
// value. Before the first successful read, failures return an error. The returned
// map is owned by the caller and can be modified without changing the cache.
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
		var values map[string]string
		err = json.Unmarshal(data, &values)
		if err == nil {
			if values == nil {
				values = make(map[string]string)
			}
			configCache.values = values
		}
	}
	if configCache.values != nil {
		return maps.Clone(configCache.values), nil
	}
	// Configuration can contain credentials. Do not include file contents or
	// decoder excerpts in errors returned to user code.
	return nil, errors.New("function: cannot read parameter configuration")
}
