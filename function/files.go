package function

import (
	"net/http"

	"github.com/tianacloud/sdk-go/files"
	"github.com/tianacloud/sdk-go/internal/functionfiles"
)

// Files constructs a client for the Function owner's tenant files root, without I/O.
func Files() *files.Client { return functionfiles.New("") }

// FilesByWebApp selects a Web subdirectory under the Function owner's files root.
// Even another tenant's Web ID cannot change that root. Construction performs no I/O.
func FilesByWebApp(webID string) (*files.Client, error) { return functionfiles.NewWeb(webID) }

// FilesFromRequest selects the Gateway-authenticated source Web's subdirectory.
// It does not authorize the caller to perform application-specific file operations.
func FilesFromRequest(r *http.Request) (*files.Client, error) {
	caller, ok := CallerFromRequest(r)
	if !ok || caller.WebID == "" {
		return nil, files.ErrNoWebContext
	}
	return FilesByWebApp(caller.WebID)
}
