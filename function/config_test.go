package function

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReadConfigInPlaceUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("FUNCTION_CONFIG_FILE", path)
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"TOKEN":`)
	if _, err := ReadConfig(); err == nil {
		t.Fatal("first incomplete read must fail")
	}
	write(`{"TOKEN":"first","MODE":"old"}`)
	values, err := ReadConfig()
	if err != nil || values["TOKEN"] != "first" {
		t.Fatalf("initial read: %v %v", values, err)
	}
	values["TOKEN"] = "caller mutation"
	write(`{"TOKEN":`)
	values, err = ReadConfig()
	if err != nil || values["TOKEN"] != "first" {
		t.Fatalf("last good read: %v %v", values, err)
	}
	write(`{"TOKEN":"second"}`)
	values, err = ReadConfig()
	if err != nil || values["TOKEN"] != "second" || len(values) != 1 {
		t.Fatalf("updated read: %v %v", values, err)
	}
	write(`{}`)
	values, err = ReadConfig()
	if err != nil || len(values) != 0 {
		t.Fatalf("empty parameters: %v %v", values, err)
	}
}

func TestReadConfigDoesNotReuseAnotherFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("FUNCTION_CONFIG_FILE", path)
	if err := os.WriteFile(path, []byte(`{"TOKEN":"first"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FUNCTION_CONFIG_FILE", path+".missing")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("changed file must not reuse the previous file's cache")
	}
	t.Setenv("FUNCTION_CONFIG_FILE", "")
	if _, err := ReadConfig(); err == nil {
		t.Fatal("missing path must fail")
	}
}

func TestReadConfigConcurrentCallersOwnTheirMaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("FUNCTION_CONFIG_FILE", path)
	if err := os.WriteFile(path, []byte(`{"MODE":"ready"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 30 {
				values, err := ReadConfig()
				if err != nil || values["MODE"] != "ready" {
					t.Errorf("read: %v %v", values, err)
					return
				}
				values["MODE"] = "local"
			}
		})
	}
	workers.Wait()
}
