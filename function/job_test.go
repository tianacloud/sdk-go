package function

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type jobTransport struct {
	target *url.URL
	next   http.RoundTripper
}

func (t jobTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "supervisor.tiana.com:80" {
		panic("unexpected job authority")
	}
	copy := r.Clone(r.Context())
	u := *r.URL
	copy.URL = &u
	copy.Host = r.URL.Host
	copy.URL.Scheme = t.target.Scheme
	copy.URL.Host = t.target.Host
	return t.next.RoundTrip(copy)
}
func TestJobRequestsUseSameEscapedID(t *testing.T) {
	var actions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Host != "supervisor.tiana.com:80" {
			t.Errorf("request: %s %s", r.Method, r.Host)
		}
		actions = append(actions, r.URL.EscapedPath())
		w.WriteHeader(200)
	}))
	defer server.Close()
	old := jobClient
	defer func() { jobClient = old }()
	u, _ := url.Parse(server.URL)
	c := *old
	c.Transport = jobTransport{u, http.DefaultTransport}
	jobClient = &c
	job, err := StartJob("中文 / job?#")
	if err != nil {
		t.Fatal(err)
	}
	if err = job.Finish(); err != nil {
		t.Fatal(err)
	}
	if err = job.Finish(); err != nil {
		t.Fatal(err)
	}
	prefix := "/jobs/" + url.PathEscape("中文 / job?#")
	if len(actions) != 3 || actions[0] != prefix+"/start" || actions[1] != prefix+"/finish" || actions[2] != actions[1] {
		t.Fatal(actions)
	}
}
