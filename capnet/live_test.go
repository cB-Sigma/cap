// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package capnet_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap/capnet"
	"github.com/cB-Sigma/cap/capxsd"
)

// The live tests read public CAP sources over the network. They are off
// unless SIGMA_CAP_LIVE=1, and they log what they found, so a run records
// the state of each source on its date. Alerts come and go: a source with
// no alert at the moment passes with a note, never by checking nothing on
// a source that has alerts.

const liveUA = "github.com/cB-Sigma/cap live tests"

func needLive(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGMA_CAP_LIVE") != "1" {
		t.Skip("set SIGMA_CAP_LIVE=1 to read the public CAP sources")
	}
}

// checkLive parses, schema-checks (content model and the OASIS schema) and
// validates each alert under the profiles it declares; it returns how many
// had errors, logging each.
func checkLive(t *testing.T, name string, items []capnet.Item) (bad int) {
	t.Helper()
	for _, it := range items {
		var probs []string
		if err := cap.ValidateSchema(it.Raw); err != nil {
			probs = append(probs, "content model: "+err.Error())
		}
		if err := capxsd.Validate(it.Raw); err != nil {
			probs = append(probs, "OASIS schema: "+err.Error())
		}
		if err := it.Alert.Validate(cap.Options{Profiles: cap.DetectProfiles(it.Alert)}); err != nil {
			probs = append(probs, err.Error())
		}
		if len(probs) > 0 {
			bad++
			t.Logf("%s: %s: %s", name, it.Alert.Identifier, strings.Join(probs, "; "))
		}
	}
	t.Logf("%s: %d alerts read, %d with errors", name, len(items), bad)
	return bad
}

// Covers: SIG-IPE-7325
//
// The US National Weather Service: the active-alerts Atom feed, each
// entry's CAP document fetched by its link (at most 25 per run).
func TestLiveNWS(t *testing.T) {
	needLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p := &capnet.Poller{URL: "https://api.weather.gov/alerts/active.atom", UserAgent: liveUA, MaxLinked: 25}
	items, err := p.Poll(ctx)
	if err != nil {
		t.Logf("poll errors: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("no alert read from the NWS feed: %v", err)
	}
	if bad := checkLive(t, "NWS", items); bad > 0 {
		t.Errorf("%d NWS alerts had errors", bad)
	}
}

// Covers: SIG-IPE-7325
//
// Environment Canada's datamart: the CAP files of the latest hour
// directories of today's offices (at most 25).
func TestLiveEnvironmentCanada(t *testing.T) {
	needLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	get := func(u string) string {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", liveUA)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return string(b)
	}
	const root = "https://dd.weather.gc.ca/today/alerts/cap/"
	hrefs := func(page, pattern string) []string {
		var out []string
		for _, m := range regexp.MustCompile(`href="(`+pattern+`)"`).FindAllStringSubmatch(page, -1) {
			out = append(out, m[1])
		}
		return out
	}
	days := hrefs(get(root), `\d{8}/`)
	if len(days) == 0 {
		t.Fatal("no day directory on the datamart")
	}
	day := root + days[len(days)-1]
	var items []capnet.Item
	for _, office := range hrefs(get(day), `[A-Z]{4}/`) {
		hours := hrefs(get(day+office), `\d\d/`)
		if len(hours) == 0 {
			continue
		}
		dir := day + office + hours[len(hours)-1]
		for _, f := range hrefs(get(dir), `[^"?/]+\.cap`) {
			if len(items) == 25 {
				break
			}
			doc := []byte(get(dir + f))
			a, err := cap.Parse(doc)
			if err != nil {
				t.Errorf("%s: %v", f, err)
				continue
			}
			items = append(items, capnet.Item{Alert: a, Raw: doc})
		}
	}
	if len(items) == 0 {
		t.Skip("no CAP file in today's latest hours on the datamart")
	}
	if bad := checkLive(t, "Environment Canada", items); bad > 0 {
		t.Errorf("%d Environment Canada alerts had errors", bad)
	}
}

// Covers: SIG-IPE-7325
//
// India's SACHET (NDMA): the national RSS feed, documents fetched by link
// (at most 25). Its alerts follow conventions the India profile reports as
// warnings; errors after RepairIndia fail the test.
func TestLiveSACHET(t *testing.T) {
	needLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	p := &capnet.Poller{URL: "https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml", UserAgent: liveUA, MaxLinked: 25}
	items, err := p.Poll(ctx)
	if err != nil {
		t.Logf("poll errors: %v", err)
	}
	if len(items) == 0 {
		t.Skipf("no SACHET alert could be read now: %v", err)
	}
	bad := 0
	for _, it := range items {
		if err := cap.ValidateSchema(it.Raw); err != nil {
			t.Logf("%s: content model: %v", it.Alert.Identifier, err)
		}
		if err := capxsd.Validate(it.Raw); err != nil {
			t.Logf("%s: OASIS schema: %v", it.Alert.Identifier, err)
		}
		cap.RepairIndia(it.Alert)
		if err := it.Alert.Validate(cap.Options{Profiles: []cap.Profile{cap.India()}}); err != nil {
			bad++
			t.Logf("%s: %v", it.Alert.Identifier, err)
		}
	}
	t.Logf("SACHET: %d alerts read, %d with errors after RepairIndia", len(items), bad)
	if bad > 0 {
		t.Errorf("%d SACHET alerts had errors", bad)
	}
}

// Covers: SIG-IPE-7325
//
// The NAAD System's TCP stream: a heartbeat arrives within two minutes
// (and any alert sent meanwhile is checked).
func TestLiveNAADS(t *testing.T) {
	needLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var items []capnet.Item
	var beat *cap.Alert
	s := &capnet.NAADSStream{
		Deliver:     func(it capnet.Item) { items = append(items, it) },
		OnHeartbeat: func(a *cap.Alert) { beat = a; cancel() },
		Report:      func(err error) { t.Logf("NAADS: %v", err) },
	}
	s.Run(ctx)
	if beat == nil {
		t.Fatal("no NAADS heartbeat within two minutes")
	}
	t.Logf("NAADS heartbeat %s sent %s, %d references", beat.Identifier, beat.Sent, len(strings.Fields(beat.References)))
	if bad := checkLive(t, "NAADS", items); bad > 0 {
		t.Errorf("%d NAADS alerts had errors", bad)
	}
}
