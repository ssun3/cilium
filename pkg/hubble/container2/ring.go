package container

import (
	"context"
	"sync"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

const defaultCapacity = 1

// A follower groups information about a follower.
type follower struct {
	ch chan *v1.Event

	// Statistics.
	sent    int
	dropped int
}

// A RecentEventsBuffer buffers recent events. Internally it uses a ring buffer
// to maintain a fixed number of events. Writing events never blocks, but reads
// will drop events if the reader cannot keep up.
type RecentEventsBuffer struct {
	sync.RWMutex

	// Ring buffer. writen and expired are refer to the number of events
	buffer  []*v1.Event
	written int
	expired int

	followers map[<-chan *v1.Event]*follower

	// Statistics.
	sent    int
	dropped int
}

// A RecentEventBufferOption sets an option on a RecentEventBuffer.
type RecentEventBufferOption func(*RecentEventsBuffer)

// WithCapacity sets the capacity.
func WithCapacity(capacity int) RecentEventBufferOption {
	return func(b *RecentEventsBuffer) {
		b.buffer = make([]*v1.Event, capacity)
	}
}

// NewRecentEventsBuffer returns a new RecentEventBuffer with the given options.
func NewRecentEventsBuffer(options ...RecentEventBufferOption) *RecentEventsBuffer {
	b := &RecentEventsBuffer{
		followers: make(map[<-chan *v1.Event]*follower),
	}
	for _, o := range options {
		o(b)
	}
	if len(b.buffer) == 0 {
		panic("zero capacity") // FIXME should we support zero capacity?
	}
	return b
}

// AllEvents returns all the events in r and then follows.
func (b *RecentEventsBuffer) AllEvents(ctx context.Context) <-chan *v1.Event {
	// FIXME chunking?
	// create channel
	// copy events to channel until head
	// add channel as follower
	// ch := make(chan *v1.Event)
	return nil // FIXME
}

// BufferedEvents returns a copy of all the events in r's buffer at the moment
// of the function call and their sequence numbers.
func (b *RecentEventsBuffer) BufferedEvents() (events []*v1.Event, written int, expired int) {
	b.RLock()
	defer b.RUnlock()
	written = b.written
	expired = b.expired
	n := written - expired
	if n == 0 {
		return
	}
	events = make([]*v1.Event, n)
	headIndex := written % len(b.buffer)
	tailIndex := expired % len(b.buffer)
	if headIndex > tailIndex {
		copy(events, b.buffer[tailIndex:headIndex])
	} else {
		copy(events[0:len(b.buffer)-headIndex], b.buffer[tailIndex:len(b.buffer)])
		copy(events[len(b.buffer)-headIndex:], b.buffer[0:headIndex])
	}
	return
}

// Cap returns r's capacity.
// FIXME is this function necessary?
func (b *RecentEventsBuffer) Cap() int {
	return len(b.buffer)
}

// Follow returns a channel with the given capacity that sends events written to
// b. capacity should be zero (unbuffered) except in special circumstances
// (testing). Events will be dropped if the reader of the returned channel
// cannot keep up.
// FIXME how to make capacity only available to test code?
func (b *RecentEventsBuffer) Follow(ctx context.Context, capacity int) <-chan *v1.Event {
	b.Lock()
	defer b.Unlock()
	f := follower{
		ch: make(chan *v1.Event, capacity),
	}
	b.followers[f.ch] = &f
	return f.ch
}

// Len returns the number of events in r at the moment of the function call.
// FIXME is this function necessary?
func (b *RecentEventsBuffer) Len() int {
	b.RLock()
	defer b.RUnlock()
	return b.written - b.expired
}

// MostRecentEvent returns the most recent event in r and its sequence number.
func (b *RecentEventsBuffer) MostRecentEvent() (*v1.Event, int) {
	b.RLock()
	defer b.RUnlock()
	if b.written == 0 {
		return nil, 0
	}
	return b.buffer[(b.written+len(b.buffer)-1)%len(b.buffer)], b.written
}

// Unfollow removes ch from the set of followers.
func (b *RecentEventsBuffer) Unfollow(ch <-chan *v1.Event) {
	b.Lock()
	defer b.Unlock()
	delete(b.followers, ch)
}

// Write writes event to r.
func (b *RecentEventsBuffer) Write(event *v1.Event) {
	b.Lock()
	defer b.Unlock()
	b.buffer[b.written%len(b.buffer)] = event
	b.written++
	if b.expired < b.written-len(b.buffer) {
		b.expired = b.written - len(b.buffer)
	}
	for _, f := range b.followers {
		select {
		case f.ch <- event:
			b.sent++
			f.sent++
		default:
			b.dropped++
			f.dropped++
		}
	}
}
