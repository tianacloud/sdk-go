// Package function provides helpers for Go programs running in Tiana Functions.
package function

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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
// Encoded parameters use FUNCTION_CONFIG_SECRET_KEY. Decryption and kind errors
// are returned even if a previous configuration is cached.
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
		var fields map[string]struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		err = json.Unmarshal(data, &fields)
		if err == nil {
			values := make(map[string]string, len(fields))
			var decoder cipher.AEAD
			for name, field := range fields {
				switch field.Kind {
				case "plain":
					values[name] = field.Value
				case "encoded":
					if decoder == nil {
						key, e := base64.StdEncoding.DecodeString(os.Getenv("FUNCTION_CONFIG_SECRET_KEY"))
						if e != nil || len(key) != 32 {
							return nil, errors.New("function: invalid parameter secret key")
						}
						block, _ := aes.NewCipher(key)
						decoder, _ = cipher.NewGCM(block)
					}
					data, e := base64.StdEncoding.DecodeString(field.Value)
					if e != nil || len(data) < decoder.NonceSize()+decoder.Overhead() {
						return nil, errors.New("function: invalid encoded parameter")
					}
					plaintext, e := decoder.Open(nil, data[:decoder.NonceSize()], data[decoder.NonceSize():], nil)
					if e != nil {
						return nil, errors.New("function: cannot decrypt parameter")
					}
					values[name] = string(plaintext)
				default:
					return nil, errors.New("function: unsupported parameter kind")
				}
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
