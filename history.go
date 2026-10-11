// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"sort"
	"sync"
	"time"
)

// History remembers the messages a receiver has seen, to check a rule
// that one message cannot show on its own: CAP-CP (0.4 rule 12, 1.0 rule
// 9) and the IPAWS profile want an Update or Cancel to reference every
// message of its chain that is still in effect. A chain is the set of
// messages joined by references; a message is in effect until the latest
// expiry of its info blocks, and for good when one has none.
//
// Add every message received (valid or not, in any order); Missing tells
// what a new message leaves out; Profile wraps that as a profile for
// Options.Profiles. A History is safe for concurrent use.
type History struct {
	mu     sync.Mutex
	msgs   map[string]histEntry
	parent map[string]string // union-find over message keys
}

type histEntry struct {
	ref     Reference
	expires time.Time // zero: no expiry
}

// NewHistory returns an empty history.
func NewHistory() *History {
	return &History{msgs: map[string]histEntry{}, parent: map[string]string{}}
}

func (h *History) find(k string) string {
	for {
		p, ok := h.parent[k]
		if !ok || p == k {
			return k
		}
		h.parent[k] = h.parent[p] // path halving
		k = p
	}
}

func (h *History) union(a, b string) {
	ra, rb := h.find(a), h.find(b)
	if ra != rb {
		h.parent[ra] = rb
	}
}

// Add records a message and joins it to the chains it references.
func (h *History) Add(a *Alert) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := a.Key()
	h.msgs[k] = histEntry{ref: Reference{a.Sender, a.Identifier, a.Sent}, expires: a.Expires()}
	if _, ok := h.parent[k]; !ok {
		h.parent[k] = k
	}
	refs, _ := ParseReferences(a.References)
	for _, r := range refs {
		if _, ok := h.parent[r.Key()]; !ok {
			h.parent[r.Key()] = r.Key()
		}
		h.union(k, r.Key())
	}
}

// Len is the number of messages recorded.
func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

// Forget drops messages that expired before t (messages without expiry
// stay), to bound the history's size.
func (h *History) Forget(t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, m := range h.msgs {
		if !m.expires.IsZero() && m.expires.Before(t) {
			delete(h.msgs, k)
		}
	}
}

// Missing returns the messages in effect at the time at, in the chains a
// references, that a does not reference itself, sorted by key. Messages
// the history has not seen cannot be reported.
func (h *History) Missing(a *Alert, at time.Time) []Reference {
	refs, err := ParseReferences(a.References)
	if err != nil || len(refs) == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	chains := map[string]bool{}
	referenced := map[string]bool{a.Key(): true}
	for _, r := range refs {
		chains[h.find(r.Key())] = true
		referenced[r.Key()] = true
	}
	var out []Reference
	for k, m := range h.msgs {
		if referenced[k] || !chains[h.find(k)] {
			continue
		}
		if m.expires.IsZero() || m.expires.After(at) {
			out = append(out, m.ref)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Profile returns a profile named "References" that reports, for an
// Update or Cancel, each message of its chains still in effect at now()
// (nil is time.Now) that it does not reference. It does not add the
// message to the history; call Add for that.
func (h *History) Profile(now func() time.Time) Profile {
	if now == nil {
		now = time.Now
	}
	return NewProfile("References", func(a *Alert) []Problem {
		if a.MsgType != "Update" && a.MsgType != "Cancel" {
			return nil
		}
		var ps []Problem
		for _, r := range h.Missing(a, now()) {
			ps = append(ps, Problem{Field: "references", Issue: "does not reference " + r.Key() + ", which is still in effect", Profile: "References",
				Rule: "CAP-CP 0.4 rule 12, 1.0 rule 9; IPAWS references"})
		}
		return ps
	})
}
