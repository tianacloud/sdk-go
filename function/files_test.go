package function

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/tianacloud/sdk-go/files"
)

func TestFilesConstructorsUseRequestWebContext(t *testing.T) {
	if Files() == nil {
		t.Fatal("tenant client")
	}
	for _, id := range []string{"web-a", "foreign-web"} {
		if _, err := FilesByWebApp(id); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := FilesFromRequest(r); !errors.Is(err, files.ErrNoWebContext) {
		t.Fatal(err)
	}
	r.Header.Set("tiana-caller-kind", "user")
	r.Header.Set("tiana-caller-tenant-id", "tenant-a")
	r.Header.Set("tiana-caller-user-id", "user-a")
	r.Header.Set("tiana-caller-web-id", "web-a")
	if _, err := FilesFromRequest(r); err != nil {
		t.Fatal(err)
	}
	r.Header.Set("tiana-caller-web-id", "../other")
	if _, err := FilesFromRequest(r); err == nil {
		t.Fatal("invalid context")
	}
}
