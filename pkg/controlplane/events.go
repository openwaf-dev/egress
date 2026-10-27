package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openwaf-dev/egress/pkg/egress"
)

// Limits of POST /v1/egress/node/events.
const (
	MaxBatchEvents = 1000
	MaxBatchBytes  = 1 << 20
	MaxPathBytes   = 2048
	MaxDetections  = 16
)

var (
	reDetectionID = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)
	reMethod      = regexp.MustCompile(`^[A-Z]{1,16}$`)
)

// EventSinkOptions tunes an EventSink; zero values take the defaults.
type EventSinkOptions struct {
	QueueSize     int           // events kept while the control plane is unreachable (default 10000)
	BatchSize     int           // events per POST, at most MaxBatchEvents (default MaxBatchEvents)
	FlushInterval time.Duration // how long an event may wait for a batch (default 2s)
	MinBackoff    time.Duration // first retry delay (default 1s)
	MaxBackoff    time.Duration // retry delay cap (default 1m)
}

// Event is one block event as sent to the control plane.
type Event struct {
	TS         string   `json:"ts"`
	OrgID      string   `json:"org_id"`
	AgentID    string   `json:"agent_id"`
	Target     string   `json:"target"`
	Code       string   `json:"code"`
	Status     int      `json:"status"`
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	IP         string   `json:"ip"`
	Detections []string `json:"detections"`
}

// Batch is the body of POST /v1/egress/node/events.
type Batch struct {
	Version int               `json:"version"`
	NodeID  string            `json:"node_id"`
	BatchID string            `json:"batch_id"`
	Events  []json.RawMessage `json:"events"`
}

// BatchResult is the control plane's answer to a batch.
type BatchResult struct {
	BatchID   string `json:"batch_id"`
	Accepted  int    `json:"accepted"`
	Dropped   int    `json:"dropped"`
	Duplicate bool   `json:"duplicate"`
}

type pendingBatch struct {
	id   string
	body []byte
	n    int
}

// EventSink queues block events of tenant agents and posts them to the control plane in
// batches. It implements egress.EventSink. The queue is bounded: when full, the oldest event
// is dropped and counted. A batch that fails is retried with backoff under the same batch_id
// (the control plane deduplicates it), so an event is delivered at most once.
type EventSink struct {
	client *Client
	opts   EventSinkOptions

	mu    sync.Mutex
	queue []json.RawMessage // ring buffer
	head  int
	size  int

	sendMu  sync.Mutex    // serializes sendNext (Run and Flush)
	pending *pendingBatch // guarded by sendMu
	wake    chan struct{}
	dropped atomic.Uint64
}

// NewEventSink returns an EventSink posting through client. Call Run to deliver events.
func NewEventSink(client *Client, opts EventSinkOptions) *EventSink {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if opts.BatchSize <= 0 || opts.BatchSize > MaxBatchEvents {
		opts.BatchSize = MaxBatchEvents
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = time.Second
	}
	if opts.MaxBackoff < opts.MinBackoff {
		opts.MaxBackoff = max(time.Minute, opts.MinBackoff)
	}
	return &EventSink{
		client: client,
		opts:   opts,
		queue:  make([]json.RawMessage, opts.QueueSize),
		wake:   make(chan struct{}, 1),
	}
}

// Dropped returns how many events were lost: dropped from a full queue or refused by the
// control plane as invalid.
func (s *EventSink) Dropped() uint64 { return s.dropped.Load() }

// Queued returns the number of events waiting for a batch.
func (s *EventSink) Queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// Block implements egress.EventSink. Events without a tenant (static mode) are ignored; an
// event the protocol would refuse (bad ids, target, status or IP) is dropped and counted.
func (s *EventSink) Block(ev egress.BlockEvent) {
	e, ok := wireEvent(ev)
	if !ok {
		if ev.TenantID != "" {
			s.dropped.Add(1)
		}
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.size == len(s.queue) {
		s.queue[s.head] = nil
		s.head = (s.head + 1) % len(s.queue)
		s.size--
		s.dropped.Add(1)
	}
	s.queue[(s.head+s.size)%len(s.queue)] = raw
	s.size++
	full := s.size >= s.opts.BatchSize
	s.mu.Unlock()
	if full {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

var validCodes = []string{
	egress.CodeInjectionDetected, egress.CodeDataLeakBlocked, egress.CodeSSRFBlocked,
	egress.CodeEgressBlocked, egress.CodeBodyTooLarge,
}

// wireEvent converts ev to the protocol shape, enforcing its limits.
func wireEvent(ev egress.BlockEvent) (Event, bool) {
	if !reUUID.MatchString(ev.TenantID) || !reUUID.MatchString(ev.AgentID) || !slices.Contains(validCodes, ev.Code) ||
		!reTargetID.MatchString(ev.Target) || ev.Status < 400 || ev.Status > 599 {
		return Event{}, false
	}
	ip, err := netip.ParseAddr(ev.IP)
	if err != nil {
		return Event{}, false
	}
	ts := ev.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	method := strings.ToUpper(ev.Method)
	if !reMethod.MatchString(method) {
		method = "OTHER"
	}
	p := eventPath(ev.Path)
	dets := []string{}
	if ev.Code == egress.CodeInjectionDetected || ev.Code == egress.CodeDataLeakBlocked {
		for _, d := range ev.Detections {
			if len(dets) == MaxDetections {
				break
			}
			if reDetectionID.MatchString(d) && !slices.Contains(dets, d) {
				dets = append(dets, d)
			}
		}
	}
	return Event{
		TS:         ts.UTC().Format(time.RFC3339Nano),
		OrgID:      ev.TenantID,
		AgentID:    ev.AgentID,
		Target:     ev.Target,
		Code:       ev.Code,
		Status:     ev.Status,
		Method:     method,
		Path:       p,
		IP:         ip.String(),
		Detections: dets,
	}, true
}

// eventPath returns p as the protocol accepts it: no query, valid UTF-8 of printable characters
// only, a leading "/" and at most MaxPathBytes bytes.
func eventPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	var b strings.Builder
	b.Grow(min(len(p)+1, MaxPathBytes))
	if !strings.HasPrefix(p, "/") {
		b.WriteByte('/')
	}
	for _, r := range p {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > MaxPathBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Run delivers events until ctx is done, then makes a last attempt (5 s) to deliver what is
// queued.
func (s *EventSink) Run(ctx context.Context) {
	ticker := time.NewTicker(s.opts.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := s.Flush(fctx); err != nil {
				log.Printf("[EGRESS] events: %d not delivered at shutdown: %v", s.Queued(), err)
			}
			cancel()
			return
		case <-ticker.C:
		case <-s.wake:
		}
		s.deliver(ctx)
	}
}

// deliver sends batches until the queue is empty, retrying a failed batch with backoff.
func (s *EventSink) deliver(ctx context.Context) {
	backoff := s.opts.MinBackoff
	for {
		err := s.sendNext(ctx)
		if errors.Is(err, errNothingToSend) || ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = s.opts.MinBackoff
			continue
		}
		log.Printf("[EGRESS] events: retrying in %s: %v", backoff, err)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(backoff*2, s.opts.MaxBackoff)
	}
}

// Flush sends every queued event, one attempt per batch, stopping at the first failure.
func (s *EventSink) Flush(ctx context.Context) error {
	for {
		if err := s.sendNext(ctx); err != nil {
			if errors.Is(err, errNothingToSend) {
				return nil
			}
			return err
		}
	}
}

var errNothingToSend = errors.New("nothing to send")

// sendNext posts the pending batch, or a new one from the queue. A batch is kept for retry
// unless the control plane accepted it or refused it as invalid.
func (s *EventSink) sendNext(ctx context.Context) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.pending == nil {
		s.pending = s.nextBatch()
		if s.pending == nil {
			return errNothingToSend
		}
	}
	b := s.pending
	status, body, err := s.client.do(ctx, http.MethodPost, EventsPath, nil, b.body)
	if err != nil {
		return fmt.Errorf("batch %s (%d events): %w", b.id, b.n, err)
	}
	switch {
	case status == http.StatusOK:
		s.pending = nil
		var res BatchResult
		if json.Unmarshal(body, &res) == nil && res.Dropped > 0 {
			log.Printf("[EGRESS] events: control plane dropped %d of %d events in batch %s", res.Dropped, b.n, b.id)
		}
		return nil
	case status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge || status == http.StatusUnprocessableEntity:
		// Resending the same bytes cannot succeed.
		s.pending = nil
		s.dropped.Add(uint64(b.n))
		log.Printf("[EGRESS] events: control plane refused batch %s (%d events): %s", b.id, b.n, errorMessage(status, body))
		return nil
	default:
		return fmt.Errorf("batch %s (%d events): %s", b.id, b.n, errorMessage(status, body))
	}
}

// nextBatch takes up to BatchSize queued events that fit MaxBatchBytes.
func (s *EventSink) nextBatch() *pendingBatch {
	id := newUUID()
	overhead := len(fmt.Sprintf(`{"version":1,"node_id":%q,"batch_id":%q,"events":[]}`, s.client.NodeID(), id))
	s.mu.Lock()
	var events []json.RawMessage
	size := overhead
	for s.size > 0 && len(events) < s.opts.BatchSize {
		e := s.queue[s.head]
		if size+len(e)+1 > MaxBatchBytes {
			break
		}
		size += len(e) + 1
		events = append(events, e)
		s.queue[s.head] = nil
		s.head = (s.head + 1) % len(s.queue)
		s.size--
	}
	s.mu.Unlock()
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(Batch{Version: 1, NodeID: s.client.NodeID(), BatchID: id, Events: events})
	if err != nil {
		s.dropped.Add(uint64(len(events)))
		return nil
	}
	return &pendingBatch{id: id, body: body, n: len(events)}
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
