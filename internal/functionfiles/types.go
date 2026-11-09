package functionfiles

import (
	"errors"
	"fmt"
	"time"
)

var ErrNoWebContext = errors.New("files: request has no source Web app")

type ListOptions struct{ Cursor string }
type GetOptions struct{ Method, Range string }
type PutOptions struct {
	Size        int64
	ContentType string
	Overwrite   bool
	WriteID     string
}
type Entry struct {
	Path         string    `json:"path"`
	IsDir        bool      `json:"is_dir"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
}
type Page struct {
	Entries    []Entry `json:"entries"`
	NextCursor string  `json:"next_cursor"`
}
type Metadata struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
	ContentType  string    `json:"content_type"`
	WriteID      string    `json:"write_id"`
}
type PutReceipt struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ETag    string `json:"etag"`
	WriteID string `json:"write_id"`
}
type Capabilities struct {
	MaxFileBytes int64 `json:"max_file_bytes"`
	WriteBlocked bool  `json:"write_blocked"`
}

// Error describes a failure without claiming that an uncertain write did not run.
// WriteID can be compared with Metadata; it is not an idempotency key.
type Error struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	Stage           string `json:"stage"`
	Outcome         string `json:"outcome"`
	DeleteConfirmed bool   `json:"delete_confirmed"`
	WriteID         string `json:"write_id"`
	StatusCode      int    `json:"-"`
	RequestID       string `json:"-"`
	cause           error
}

func (e *Error) Error() string {
	return fmt.Sprintf("files: %s (stage=%s, outcome=%s, request_id=%s)", e.Code, e.Stage, e.Outcome, e.RequestID)
}
func (e *Error) Unwrap() error { return e.cause }
