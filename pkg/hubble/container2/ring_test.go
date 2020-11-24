package container

import (
	"context"
	"fmt"
	"testing"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecentEventsBufferEmpty(t *testing.T) {
	for _, capacity := range []int{1, 4, 15} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			b := NewRecentEventsBuffer(
				WithCapacity(capacity),
			)
			require.NotNil(t, b)

			assert.Equal(t, capacity, b.Cap())
			assert.Equal(t, 0, b.Len())

			bufferedEvents, written, expired := b.BufferedEvents()
			assert.Len(t, bufferedEvents, 0)
			assert.Equal(t, 0, written)
			assert.Equal(t, 0, expired)

			event, seq := b.MostRecentEvent()
			assert.Nil(t, event)
			assert.Zero(t, seq)
		})
	}
}

func TestRecentEventsBufferFollowUnfollow(t *testing.T) {
	for _, capacity := range []int{1, 4, 15} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			b := NewRecentEventsBuffer(
				WithCapacity(4),
			)
			require.NotNil(t, b)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Fill the buffer with unique events.
			for i := 0; i < capacity; i++ {
				b.Write(&v1.Event{})
			}

			// Create a buffered channel that can receive one event without blocking.
			ch := b.Follow(ctx, 1)

			// Test that an event is received.
			event1 := &v1.Event{}
			b.Write(event1)
			select {
			case event := <-ch:
				assert.Equal(t, event1, event)
			default:
				assert.Fail(t, "no event received")
			}

			// Test that events that cannot be received are dropped.
			b.Write(&v1.Event{})
			event2 := &v1.Event{}
			b.Write(event2)
			select {
			case event := <-ch:
				assert.Equal(t, event2, event)
			default:
				assert.Fail(t, "no event received")
			}

			// Check the follower's statistics.
			for _, f := range b.followers {
				assert.Equal(t, 2, f.sent)
				assert.Equal(t, 1, f.dropped)
			}

			// Test that no events are received after calling Unfollow.
			b.Unfollow(ch)
			b.Write(&v1.Event{})
			select {
			case <-ch:
				assert.Fail(t, "unexpected recieve")
			default:
			}

			// Check statistics.
			assert.Equal(t, capacity+4, b.written, "written")
			assert.Equal(t, capacity, b.expired, "expired")
			assert.Equal(t, 2, b.sent, "sent")
			assert.Equal(t, 1, b.dropped, "dropped")
		})
	}
}

func TestRecentEventsBufferWrite(t *testing.T) {
	for _, capacity := range []int{1, 4, 15} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			b := NewRecentEventsBuffer(
				WithCapacity(capacity),
			)
			require.NotNil(t, b)

			events := makeUnqiueEvents(3 * capacity)

			// Fill the the buffer with unique events.
			for i := 0; i < capacity; i++ {
				t.Run(fmt.Sprintf("event_%d", i), func(t *testing.T) {
					b.Write(events[i])

					assert.Equal(t, i+1, b.Len())

					mostRecentEvents, seq := b.MostRecentEvent()
					assert.Equal(t, events[i], mostRecentEvents)
					assert.Equal(t, i+1, seq)

					bufferedEvents, written, expired := b.BufferedEvents()
					assert.Equal(t, events[0:i+1], bufferedEvents)
					assert.Equal(t, i+1, written)
					assert.Zero(t, expired)
				})
			}

			// Write more events to fill the buffer twice.
			for i := capacity; i < 3*capacity; i++ {
				t.Run(fmt.Sprintf("event_%d", i), func(t *testing.T) {
					b.Write(events[i])

					assert.Equal(t, capacity, b.Len())

					mostRecentEvents, seq := b.MostRecentEvent()
					assert.Equal(t, events[i], mostRecentEvents)
					assert.Equal(t, i+1, seq)

					bufferedEvents, written, expired := b.BufferedEvents()
					assert.Equal(t, events[len(events)-capacity:], bufferedEvents)
					assert.Equal(t, i+1, written)
					assert.Equal(t, i+1-capacity, expired)
				})
			}
		})
	}
}

func TestRecentEventsBufferZeroCapacity(t *testing.T) {
	assert.Panics(t, func() {
		_ = NewRecentEventsBuffer()
	})
}

// makeUniqueEvents returns a slice of n unique events.
func makeUnqiueEvents(n int) []*v1.Event {
	events := make([]*v1.Event, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, &v1.Event{})
	}
	return events
}
