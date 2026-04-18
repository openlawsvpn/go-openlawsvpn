// Package reliable implements the OpenVPN3 reliable control-channel transport:
// sequence numbers, ACK handling, retransmit queue, and a sliding receive window.
//
// Reference: openvpn3-core reliable/reliable.hpp
package reliable

import (
	"sync"
	"time"
)

// WindowSize is the maximum number of unacknowledged in-flight packets.
// Matches openvpn3-core RELIABLE_WINDOW (8).
const WindowSize = 8

// RetransmitTimeout is the initial retransmit interval.
// openvpn3-core uses 2 s with exponential back-off.
const RetransmitTimeout = 2 * time.Second

// Entry is a single outgoing packet held in the retransmit queue.
type Entry struct {
	PacketID  uint32
	Payload   []byte
	SentAt    time.Time
	Retries   int
	NextRetry time.Time
}

// SendQueue manages the sliding window of unacknowledged outgoing packets.
type SendQueue struct {
	mu      sync.Mutex
	entries []*Entry
	nextID  uint32
}

// Enqueue adds payload to the send queue and returns the assigned packet ID.
// It never drops: the queue is unbounded so large TLS records (which fragment
// into many P_CONTROL_V1 segments) can all be tracked for retransmit.
func (q *SendQueue) Enqueue(payload []byte) (uint32, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := q.nextID
	q.nextID++
	now := time.Now()
	e := &Entry{
		PacketID:  id,
		Payload:   payload,
		SentAt:    now,
		NextRetry: now.Add(RetransmitTimeout),
	}
	q.entries = append(q.entries, e)
	return id, nil
}

// Ack removes the entry with the given packet ID from the queue.
// It is safe to call with an ID that is not in the queue (idempotent).
func (q *SendQueue) Ack(packetID uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.PacketID == packetID {
			q.entries = append(q.entries[:i], q.entries[i+1:]...)
			return
		}
	}
}

// AckMany removes all entries whose packet IDs appear in ids.
func (q *SendQueue) AckMany(ids []uint32) {
	for _, id := range ids {
		q.Ack(id)
	}
}

// DueForRetransmit returns entries whose NextRetry deadline has passed.
// It updates each returned entry's NextRetry and Retries counter.
func (q *SendQueue) DueForRetransmit() []*Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	var due []*Entry
	for _, e := range q.entries {
		if now.After(e.NextRetry) {
			e.Retries++
			// Exponential back-off, capped at 30 s.
			backoff := RetransmitTimeout * (1 << e.Retries)
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			e.NextRetry = now.Add(backoff)
			due = append(due, e)
		}
	}
	return due
}

// Len returns the current number of unacknowledged entries.
func (q *SendQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// NextID returns the packet ID that will be assigned to the next Enqueue call.
// Use this to build the wire packet before calling Enqueue.
func (q *SendQueue) NextID() uint32 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.nextID
}

// RecvWindow is a sliding receive window that delivers packets in order
// and discards duplicates / out-of-range packets.
type RecvWindow struct {
	mu       sync.Mutex
	expected uint32
	// pending holds out-of-order packets keyed by packet_id.
	pending map[uint32][]byte
}

// NewRecvWindow creates a RecvWindow expecting the first packet ID to be 0.
func NewRecvWindow() *RecvWindow {
	return &RecvWindow{pending: make(map[uint32][]byte)}
}

// NewRecvWindowFrom creates a RecvWindow expecting the first packet ID to be firstExpected.
func NewRecvWindowFrom(firstExpected uint32) *RecvWindow {
	return &RecvWindow{expected: firstExpected, pending: make(map[uint32][]byte)}
}

// NewSendQueue creates a SendQueue that assigns packet IDs starting from firstPacketID.
func NewSendQueue(firstPacketID uint32) *SendQueue {
	return &SendQueue{nextID: firstPacketID}
}

// Receive delivers a packet to the window.
// It returns:
//   - (payloads, ackIDs): payloads contains one or more in-order packets
//     ready for the upper layer; ackIDs contains all packet IDs that must
//     be ACKed (both newly accepted and already-held ones that became ready).
//
// Duplicate packets (already accepted) are silently dropped and still ACKed.
// Packets outside the window are dropped and not ACKed.
func (w *RecvWindow) Receive(packetID uint32, payload []byte) (payloads [][]byte, ackIDs []uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Drop if too far behind (already delivered).
	if packetID < w.expected {
		return nil, nil
	}

	// Drop if too far ahead (outside window).
	if packetID >= w.expected+WindowSize {
		return nil, nil
	}

	// Store in pending (idempotent — overwriting is safe for immutable payloads).
	w.pending[packetID] = payload
	ackIDs = append(ackIDs, packetID)

	// Deliver all consecutive packets starting from expected.
	for {
		p, ok := w.pending[w.expected]
		if !ok {
			break
		}
		payloads = append(payloads, p)
		delete(w.pending, w.expected)
		w.expected++
	}
	return payloads, ackIDs
}

// Expected returns the next packet ID the window expects.
func (w *RecvWindow) Expected() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.expected
}
