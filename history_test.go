// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap_test

import (
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

// History reports the messages of a chain still in effect that an Update
// or Cancel leaves out of its references; expired messages, other chains
// and messages it references are not reported.
func TestHistory(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	msg := func(id, typ, refs string, sent time.Time, expires time.Duration) *cap.Alert {
		a := rainAlert(id, typ, "Severe", refs, sent)
		for i := range a.Info {
			a.Info[i].Expires = ""
			if expires > 0 {
				a.Info[i].Expires = cap.FormatTime(sent.Add(expires))
			}
		}
		return a
	}
	h := cap.NewHistory()
	a1 := msg("A1", "Alert", "", t0, 0) // never expires
	a2 := msg("A2", "Update", a1.Key(), t0.Add(time.Hour), 2*time.Hour)
	a3 := msg("A3", "Alert", "", t0, time.Hour)                            // another chain
	old := msg("A0", "Update", a1.Key(), t0.Add(time.Minute), time.Minute) // expired
	for _, a := range []*cap.Alert{a1, a2, a3, old} {
		h.Add(a)
	}
	if h.Len() != 4 {
		t.Fatalf("Len = %d", h.Len())
	}
	at := t0.Add(90 * time.Minute)
	// An update referring only to A2 misses A1 (no expiry), not A0 (expired) or A3.
	u := msg("A4", "Update", a2.Key(), at, time.Hour)
	if m := h.Missing(u, at); len(m) != 1 || m[0].Identifier != "A1" {
		t.Fatalf("Missing = %v", m)
	}
	p := h.Profile(func() time.Time { return at })
	if ps := p.Check(u); !find(ps, "References", "references", "A1", false) || len(ps) != 1 {
		t.Errorf("profile:\n%s", dump(ps))
	}
	full := msg("A5", "Cancel", a1.Key()+" "+a2.Key(), at, time.Hour)
	if ps := p.Check(full); len(ps) != 0 {
		t.Errorf("complete references:\n%s", dump(ps))
	}
	if ps := p.Check(a3); len(ps) != 0 {
		t.Errorf("an Alert was checked:\n%s", dump(ps))
	}
	// After A2 expires, an update referring to A1 alone is complete.
	later := t0.Add(4 * time.Hour)
	if m := h.Missing(msg("A6", "Update", a1.Key(), later, time.Hour), later); len(m) != 0 {
		t.Errorf("after expiry: %v", m)
	}
	h.Forget(later)
	if h.Len() != 1 {
		t.Errorf("Len after Forget = %d, want 1 (A1 never expires)", h.Len())
	}
	// Concurrent use.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Add(msg("C", "Update", a1.Key(), later, time.Hour))
			_ = h.Missing(u, at)
		}()
	}
	wg.Wait()
}
