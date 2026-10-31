package function

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCallerFromGatewayRequests(t *testing.T) {
	path := os.Getenv("TIANA_FUNCTION_CALLER_REQUESTS")
	if path == "" {
		t.Skip("requires requests captured from the real Gateway ingress")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var requests map[string]string
	if err := json.Unmarshal(raw, &requests); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 6 {
		t.Fatalf("captured %d requests, want six", len(requests))
	}
	for path, wire := range requests {
		request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
		if err != nil {
			t.Fatal(err)
		}
		caller, ok := CallerFromRequest(request)
		_ = request.Body.Close()
		if strings.Contains(path, "machine") {
			if ok {
				t.Fatal("machine request acquired a user")
			}
			continue
		}
		suffix := "a"
		if strings.Contains(path, "user-b") {
			suffix = "b"
		}
		if !ok || caller != (Caller{UserID: "user-" + suffix, TenantID: "selected-" + suffix, AppOwnerID: "user-a"}) || caller.IsAppOwner() != (suffix == "a") {
			t.Fatal("Gateway and SDK request identities differ")
		}
	}
}

func TestCallerFromRequest(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers http.Header
		valid   bool
	}{
		{"machine", nil, false},
		{"user", http.Header{"Tiana-Caller-User-Id": {"user-1"}, "Tiana-Caller-Tenant-Id": {"selected-tenant"}}, true},
		{"case", http.Header{"TIANA-CALLER-USER-ID": {"user-1"}, "tiana-caller-tenant-id": {"selected-tenant"}}, true},
		{"partial", http.Header{"Tiana-Caller-User-Id": {"user-1"}}, false},
		{"duplicate", http.Header{"Tiana-Caller-User-Id": {"user-1", "user-2"}, "Tiana-Caller-Tenant-Id": {"selected-tenant"}}, false},
		{"duplicate case", http.Header{"Tiana-Caller-User-Id": {"user-1"}, "tiana-caller-user-id": {"user-2"}, "Tiana-Caller-Tenant-Id": {"selected-tenant"}}, false},
		{"empty", http.Header{"Tiana-Caller-User-Id": {""}, "Tiana-Caller-Tenant-Id": {"selected-tenant"}}, false},
		{"merged", http.Header{"Tiana-Caller-User-Id": {"user-1,user-2"}, "Tiana-Caller-Tenant-Id": {"selected-tenant"}}, false},
		{"bad tenant", http.Header{"Tiana-Caller-User-Id": {"user-1"}, "Tiana-Caller-Tenant-Id": {"tenant\r\nx: y"}}, false},
		{"long", http.Header{"Tiana-Caller-User-Id": {strings.Repeat("x", 129)}, "Tiana-Caller-Tenant-Id": {"selected-tenant"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header = test.headers
			caller, ok := CallerFromRequest(r)
			if ok != test.valid {
				t.Fatalf("present=%v want %v", ok, test.valid)
			}
			if ok && caller != (Caller{UserID: "user-1", TenantID: "selected-tenant"}) {
				t.Fatal("wrong request identity")
			}
			if !ok && caller != (Caller{}) {
				t.Fatal("partial identity returned")
			}
		})
	}
	if _, ok := CallerFromRequest(nil); ok {
		t.Fatal("nil request has identity")
	}
}

func TestCallerHTTPDeclaration(t *testing.T) {
	raw, err := os.ReadFile("caller-context.json")
	if err != nil {
		t.Fatal(err)
	}
	var declaration map[string]string
	if err := json.Unmarshal(raw, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration["user_id_header"] != callerUserHeader || declaration["tenant_id_header"] != callerTenantHeader || declaration["app_owner_id_header"] != callerAppOwnerHeader {
		t.Fatal("HTTP consumer differs from shared declaration")
	}
}

func TestCallerIsAppOwner(t *testing.T) {
	for _, tc := range []struct {
		name         string
		owners       []string
		valid, owner bool
	}{
		{"creator", []string{"user-1"}, true, true},
		{"another creator", []string{"user-2"}, true, false},
		{"no Web", nil, true, false},
		{"empty owner", []string{""}, false, false},
		{"duplicate", []string{"user-1", "user-2"}, false, false},
		{"invalid owner", []string{"user\r\nother: value"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set(callerUserHeader, "user-1")
			r.Header.Set(callerTenantHeader, "tenant-1")
			if tc.owners != nil {
				r.Header["TIANA-CALLER-APP-OWNER-ID"] = tc.owners
			}
			caller, ok := CallerFromRequest(r)
			if ok != tc.valid || caller.IsAppOwner() != tc.owner {
				t.Fatal("unexpected Web creator identity")
			}
		})
	}
	if (Caller{}).IsAppOwner() {
		t.Fatal("empty caller is not a creator")
	}
}
