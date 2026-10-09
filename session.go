package tiana

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const receiveWindow = 65535
const frameSize = 16384

type frameWrite struct {
	t           *Tunnel
	reserved    int64
	opensStream bool
	cleanup     func()
	write       func(*http2.Framer) error
	result      chan error
}

type session struct {
	mu                            sync.Mutex
	conn                          net.Conn
	cfg                           Config
	reader, writer                *http2.Framer
	writes                        chan frameWrite
	headersGate                   chan struct{}
	resetReady                    chan struct{}
	pendingResets                 map[uint32]struct{}
	changed, ready, done, stopped chan struct{}
	readyOnce                     sync.Once
	workers                       sync.WaitGroup
	streams                       map[uint32]*Tunnel
	nextID                        uint32
	sendWindow, initialWindow     int64
	maxStreams                    uint32
	draining                      bool
	err                           error
}

func newSession(conn net.Conn, cfg Config) *session {
	reader := http2.NewFramer(nil, conn)
	reader.SetMaxReadFrameSize(frameSize)
	reader.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	reader.ReadMetaHeaders.SetAllowedMaxDynamicTableSize(0)
	reader.MaxHeaderListSize = frameSize
	return &session{conn: conn, cfg: cfg, reader: reader, writer: http2.NewFramer(conn, nil),
		writes: make(chan frameWrite, 128), headersGate: make(chan struct{}, 1), resetReady: make(chan struct{}, 1), pendingResets: make(map[uint32]struct{}), changed: make(chan struct{}), ready: make(chan struct{}), done: make(chan struct{}), stopped: make(chan struct{}),
		streams: make(map[uint32]*Tunnel), nextID: 1, sendWindow: 65535, initialWindow: 65535, maxStreams: uint32(cfg.MaxStreams)}
}

func (s *session) signalLocked() { close(s.changed); s.changed = make(chan struct{}) }

func (s *session) start() {
	s.workers.Add(2)
	go func() { defer s.workers.Done(); s.writeLoop() }()
	go func() { defer s.workers.Done(); s.readLoop() }()
	go func() { s.workers.Wait(); close(s.stopped) }()
}

func (s *session) writeLoop() {
	// Shutdown and enqueue use the same mutex, so no producer can enqueue after
	// the final drain. Dispose queued payloads even when they never reach TLS.
	defer func() {
		for {
			select {
			case request := <-s.writes:
				if request.cleanup != nil {
					request.cleanup()
				}
			default:
				return
			}
		}
	}()
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.ConnectTimeout))
	_, err := io.WriteString(s.conn, http2.ClientPreface)
	if err == nil {
		err = s.writer.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0},
			http2.Setting{ID: http2.SettingEnablePush, Val: 0},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: receiveWindow},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: frameSize})
	}
	if err != nil {
		s.shutdown(failure(HTTP2, "preface write failed", false))
		return
	}
	for {
		s.mu.Lock()
		if s.err != nil {
			s.mu.Unlock()
			return
		}
		var reset uint32
		for id := range s.pendingResets {
			reset = id
			delete(s.pendingResets, id)
			break
		}
		s.mu.Unlock()
		if reset != 0 {
			_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.ConnectTimeout))
			if err := s.writer.WriteRSTStream(reset, http2.ErrCodeCancel); err != nil {
				s.shutdown(failure(HTTP2, "reset write failed", false))
				return
			}
			continue
		}
		select {
		case <-s.done:
			return
		case <-s.resetReady:
			continue
		case request := <-s.writes:
			s.mu.Lock()
			s.signalLocked()
			err := s.err
			if request.t != nil && request.t.err != nil {
				err = request.t.err
			}
			if err != nil && request.reserved > 0 {
				s.sendWindow += request.reserved
				if request.t != nil {
					request.t.sendWindow += request.reserved
				}
				s.signalLocked()
			}
			if err == nil && request.opensStream {
				request.t.headersStarted = true
			}
			s.mu.Unlock()
			if err == nil {
				_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.ConnectTimeout))
				if writeErr := request.write(s.writer); writeErr != nil {
					err = failure(HTTP2, "frame write failed", false)
					s.shutdown(err)
				}
			}
			if request.cleanup != nil {
				request.cleanup()
			}
			if request.result != nil {
				request.result <- err
			}
		}
	}
}

func (s *session) enqueue(request frameWrite) error {
	for {
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return err
		}
		select {
		case s.writes <- request:
			s.mu.Unlock()
			return nil
		default:
		}
		changed := s.changed
		s.mu.Unlock()
		<-changed
	}
}

func (s *session) control(write func(*http2.Framer) error) { _ = s.enqueue(frameWrite{write: write}) }

func (s *session) shutdown(err error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	s.err = err
	for _, t := range s.streams {
		t.failLocked(err)
	}
	clear(s.streams)
	clear(s.pendingResets)
	close(s.done)
	s.readyOnce.Do(func() { close(s.ready) })
	s.signalLocked()
	s.mu.Unlock()
	_ = s.conn.Close()
}

func (s *session) abort(t *Tunnel, err error) {
	s.mu.Lock()
	idleDraining := s.abortLocked(t, err)
	s.mu.Unlock()
	if idleDraining {
		s.shutdown(failure(Closed, "drained connection", false))
	}
}

// abortLocked commits the stream failure while holding mu. Deadline handlers
// use this to make rechecking a changed deadline and termination atomic.
func (s *session) abortLocked(t *Tunnel, err error) bool {
	if t.err != nil {
		return false
	}
	alreadyFinished := t.finished
	t.failLocked(err)
	delete(s.streams, t.id)
	s.signalLocked()
	idleDraining := s.draining && len(s.streams) == 0
	if !alreadyFinished && t.headersStarted && !idleDraining && s.err == nil {
		s.pendingResets[t.id] = struct{}{}
		select {
		case s.resetReady <- struct{}{}:
		default:
		}
	}
	return idleDraining
}

// startTunnel orders newly opened streams without holding the session state
// mutex across queue or physical I/O waits. The response waits independently.
func (s *session) startTunnel(ctx context.Context, profile Profile, requestID string) (*Tunnel, error) {
	select {
	case s.headersGate <- struct{}{}:
	case <-ctx.Done():
		return nil, contextFailure(ctx.Err(), false)
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return nil, s.err
	}
	defer func() { <-s.headersGate }()
	if err := ctx.Err(); err != nil {
		return nil, contextFailure(err, false)
	}
	t, err := s.open(profile, requestID)
	if err != nil {
		return nil, err
	}
	go t.watch(ctx, s.cfg.ResponseTimeout)
	if err := s.sendHeaders(t); err != nil {
		s.abort(t, err)
	}
	return t, nil
}

func (s *session) open(profile Profile, requestID string) (*Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if s.draining {
		return nil, failure(HTTP2, "connection draining", false)
	}
	if len(s.streams) >= s.cfg.MaxStreams || uint32(len(s.streams)) >= s.maxStreams {
		return nil, failure(Limit, "concurrent stream limit reached", false)
	}
	if s.nextID > 0x7fffffff {
		s.draining = true
		return nil, failure(Limit, "stream IDs exhausted", false)
	}
	t := &Tunnel{s: s, id: s.nextID, meta: Metadata{Endpoint: s.cfg.Endpoint, Profile: profile, RequestID: requestID},
		ready: make(chan struct{}), done: make(chan struct{}), failed: make(chan struct{}), sendWindow: s.initialWindow, recvWindow: receiveWindow}
	s.nextID += 2
	s.streams[t.id] = t
	return t, nil
}

func (s *session) sendHeaders(t *Tunnel) error {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	encoder.SetMaxDynamicTableSizeLimit(0)
	encoder.SetMaxDynamicTableSize(0)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: s.cfg.Endpoint + ":443"},
		{Name: "tiana-tunnel-version", Value: "1"}, {Name: "tiana-database-protocol", Value: string(t.meta.Profile)},
		{Name: "tiana-request-id", Value: t.meta.RequestID}, {Name: "user-agent", Value: s.cfg.UserAgent},
	}
	if s.cfg.Token != nil {
		fields = append(fields, hpack.HeaderField{Name: "proxy-authorization", Value: "Bearer " + s.cfg.Token.value, Sensitive: true})
	}
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return failure(HTTP2, "header encoding failed", false)
		}
	}
	data := block.Bytes()
	return t.send(frameWrite{t: t, opensStream: true, cleanup: func() { clear(data) }, write: func(f *http2.Framer) error {
		return f.WriteHeaders(http2.HeadersFrameParam{StreamID: t.id, EndHeaders: true, BlockFragment: data})
	}}, false)
}

func (s *session) readLoop() {
	first := true
	for {
		frame, err := s.reader.ReadFrame()
		if err != nil {
			var streamErr http2.StreamError
			if errors.As(err, &streamErr) {
				s.mu.Lock()
				t := s.streams[streamErr.StreamID]
				s.mu.Unlock()
				if t != nil {
					s.abort(t, failure(Response, "invalid response headers", false))
					continue
				}
			}
			s.shutdown(failure(HTTP2, "connection read failed", false))
			return
		}
		if first {
			settings, ok := frame.(*http2.SettingsFrame)
			if !ok || settings.IsAck() {
				s.shutdown(failure(HTTP2, "server preface must be SETTINGS", false))
				return
			}
			first = false
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := s.settings(f); err != nil {
					s.shutdown(err)
					return
				}
				s.control(func(w *http2.Framer) error { return w.WriteSettingsAck() })
				s.readyOnce.Do(func() { close(s.ready) })
			}
		case *http2.MetaHeadersFrame:
			s.headers(f)
		case *http2.DataFrame:
			s.data(f)
		case *http2.WindowUpdateFrame:
			if !s.windowUpdate(f) {
				s.shutdown(failure(HTTP2, "flow-control window overflow", false))
				return
			}
		case *http2.RSTStreamFrame:
			s.mu.Lock()
			if t := s.streams[f.StreamID]; t != nil {
				e := failure(HTTP2, "stream reset", t.committed)
				e.Unprocessed = !t.committed && f.ErrCode == http2.ErrCodeRefusedStream
				t.failLocked(e)
				delete(s.streams, t.id)
				s.signalLocked()
			}
			s.mu.Unlock()
		case *http2.GoAwayFrame:
			s.mu.Lock()
			s.draining = true
			for id, t := range s.streams {
				if id > f.LastStreamID {
					e := failure(HTTP2, "GOAWAY excluded stream", t.committed)
					e.Unprocessed = !t.committed
					t.failLocked(e)
					delete(s.streams, id)
				}
			}
			idle := len(s.streams) == 0
			s.signalLocked()
			s.mu.Unlock()
			if idle {
				s.shutdown(failure(Closed, "drained connection", false))
				return
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				s.control(func(w *http2.Framer) error { return w.WritePing(true, data) })
			}
		case *http2.PushPromiseFrame:
			s.shutdown(failure(HTTP2, "server push is disabled", false))
			return
		}
	}
}

func (s *session) settings(f *http2.SettingsFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := f.ForeachSetting(func(setting http2.Setting) error {
		if setting.Valid() != nil {
			return failure(HTTP2, "invalid SETTINGS", false)
		}
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			delta := int64(setting.Val) - s.initialWindow
			for _, t := range s.streams {
				t.sendWindow += delta
				if t.sendWindow > 0x7fffffff {
					return failure(HTTP2, "flow-control window overflow", false)
				}
			}
			s.initialWindow = int64(setting.Val)
		case http2.SettingMaxConcurrentStreams:
			s.maxStreams = setting.Val
		}
		return nil
	})
	s.signalLocked()
	return err
}

func (s *session) windowUpdate(f *http2.WindowUpdateFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	window := &s.sendWindow
	if f.StreamID != 0 {
		t := s.streams[f.StreamID]
		if t == nil {
			return true
		}
		window = &t.sendWindow
	}
	*window += int64(f.Increment)
	s.signalLocked()
	return *window <= 0x7fffffff
}

func (s *session) headers(f *http2.MetaHeadersFrame) {
	s.mu.Lock()
	t := s.streams[f.StreamID]
	if t == nil {
		s.mu.Unlock()
		return
	}
	if t.committed {
		s.mu.Unlock()
		s.abort(t, failure(Response, "unexpected response trailers", true))
		return
	}
	status, statusErr := strconv.Atoi(f.PseudoValue("status"))
	if status == 200 {
		t.committed = true
	}
	if statusErr != nil || status < 100 || status > 599 || f.Truncated || len(f.Fields) > 64 {
		s.mu.Unlock()
		s.abort(t, failure(Response, "invalid response headers", t.committed))
		return
	}
	values := make(map[string]string, len(f.Fields))
	for _, field := range f.Fields {
		if _, duplicate := values[field.Name]; duplicate {
			s.mu.Unlock()
			s.abort(t, failure(Response, "duplicate response header", t.committed))
			return
		}
		values[field.Name] = field.Value
	}
	if status != 200 {
		e := failure(Gateway, "CONNECT rejected", false)
		e.Status = status
		if validErrorCode(values["tiana-error-code"]) {
			e.Code = values["tiana-error-code"]
		}
		if millis, err := strconv.ParseUint(values["tiana-retry-after-ms"], 10, 32); err == nil && millis >= 1 && millis <= 60000 {
			e.RetryAfter = time.Duration(millis) * time.Millisecond
		}
		s.mu.Unlock()
		s.abort(t, e)
		return
	}
	mode := values["tiana-auth-mode"]
	if len(values) != 4 || values["tiana-tunnel-version"] != "1" || values["tiana-request-id"] != t.meta.RequestID || (mode != "TOKEN_REQUIRED" && mode != "DISABLED") {
		s.mu.Unlock()
		s.abort(t, failure(Response, "invalid success header set", true))
		return
	}
	t.meta.AuthMode = mode
	t.remoteEOF = f.StreamEnded()
	t.readyOnce.Do(func() { close(t.ready) })
	s.signalLocked()
	s.mu.Unlock()
}

func validErrorCode(value string) bool {
	switch value {
	case "QUOTA_EXCEEDED", "MALFORMED_CONNECT", "EARLY_TUNNEL_DATA", "AUTH_REQUIRED", "ACCESS_DENIED", "AUTHORIZATION_EXPIRED", "CALLER_DEADLINE", "ENDPOINT_MISMATCH", "CONNECTION_LIMIT", "POLICY_UNAVAILABLE", "INSTANCE_UNAVAILABLE", "ACTIVATION_TIMEOUT", "ACTIVATION_RESOURCE_PRESSURE", "ACTIVATION_NO_IDLE_POD", "ACTIVATION_CAPACITY_UNAVAILABLE":
		return true
	default:
		return false
	}
}

func (s *session) data(f *http2.DataFrame) {
	data := f.Data()
	flow := int64(f.Header().Length)
	s.mu.Lock()
	t := s.streams[f.StreamID]
	if t == nil {
		s.mu.Unlock()
		if flow > 0 {
			s.control(func(w *http2.Framer) error { return w.WriteWindowUpdate(0, uint32(flow)) })
		}
		return
	}
	if !t.committed || t.remoteEOF || flow > t.recvWindow {
		s.mu.Unlock()
		s.abort(t, failure(HTTP2, "unexpected DATA or flow-control violation", t.committed))
		return
	}
	t.recvWindow -= flow
	_, _ = t.buffer.Write(data)
	padding := flow - int64(len(data))
	t.recvWindow += padding
	if f.StreamEnded() {
		t.remoteEOF = true
		t.finishLocked()
	}
	s.signalLocked()
	idle := s.draining && len(s.streams) == 0
	s.mu.Unlock()
	if flow > 0 {
		s.control(func(w *http2.Framer) error { return w.WriteWindowUpdate(0, uint32(flow)) })
	}
	if padding > 0 && !f.StreamEnded() {
		s.control(func(w *http2.Framer) error { return w.WriteWindowUpdate(f.StreamID, uint32(padding)) })
	}
	if idle {
		s.shutdown(failure(Closed, "drained connection", false))
	}
}
