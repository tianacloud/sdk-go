package function

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Job keeps the current backend execution alive until Finish is called.
// IDs identify active work in one execution; after Finish an ID may be reused.
type Job struct{ id string }

var jobClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil},
	Timeout:       30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// StartJob registers work before launching a goroutine or returning an HTTP
// response. Repeating StartJob for an active ID does not increase its count.
func StartJob(id string) (*Job, error) {
	if id == "" {
		return nil, errors.New("function: job ID is empty")
	}
	job := &Job{id: id}
	if err := job.call("start"); err != nil {
		return nil, err
	}
	return job, nil
}

// Finish releases this job. Finishing an unknown or finished ID succeeds.
// A failed Finish can be retried; a program restart clears all registrations.
func (j *Job) Finish() error { return j.call("finish") }

func (j *Job) call(action string) error {
	if j == nil || j.id == "" {
		return errors.New("function: invalid job")
	}
	response, err := jobClient.Get("http://supervisor.tiana.com:80/jobs/" + url.PathEscape(j.id) + "/" + action)
	if err != nil {
		return errors.New("function: job request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("function: job request returned HTTP %d", response.StatusCode)
	}
	return nil
}
