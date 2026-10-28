package function

import (
	"net/http"
	"strings"
)

const (
	callerUserHeader   = "tiana-caller-user-id"
	callerTenantHeader = "tiana-caller-tenant-id"
)

// Caller identifies the authenticated user and the tenant selected in their
// session. TenantID is not necessarily the function owner's tenant.
type Caller struct {
	UserID   string
	TenantID string
}

// CallerFromRequest reads the identity delivered by Tiana Gateway for this
// request. Machine-token requests have no caller. The complete pair must be
// present exactly once and valid; absent or malformed identity returns false.
// This consumes Gateway's authorization result, not credentials: use it only
// behind the platform's managed Function HTTP entry.
func CallerFromRequest(request *http.Request) (Caller, bool) {
	if request == nil {
		return Caller{}, false
	}
	var caller Caller
	var users, tenants int
	for name, values := range request.Header {
		switch {
		case strings.EqualFold(name, callerUserHeader):
			users += len(values)
			if len(values) == 1 {
				caller.UserID = values[0]
			}
		case strings.EqualFold(name, callerTenantHeader):
			tenants += len(values)
			if len(values) == 1 {
				caller.TenantID = values[0]
			}
		}
	}
	if users != 1 || tenants != 1 || !validCallerID(caller.UserID) || !validCallerID(caller.TenantID) {
		return Caller{}, false
	}
	return caller, true
}

func validCallerID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '.' || c == '_' || c == ':' || c == '-') {
			continue
		}
		return false
	}
	return true
}
