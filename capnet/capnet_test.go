// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package capnet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap/capnet"
	"github.com/cB-Sigma/cap/capxsd"
)

func alertDoc(t *testing.T, id string, refs string) []byte {
	t.Helper()
	a := &cap.Alert{Identifier: id, Sender: "met@example.test", Sent: "2026-10-12T01:00:00+05:30",
		Status: "Actual", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{Category: []string{"Met"}, Event: "Rain", Urgency: "Expected", Severity: "Moderate", Certainty: "Likely",
			Headline: "Rain " + id, Expires: "2099-01-01T00:00:00+05:30"}}}
	if refs != "" {
		a.MsgType, a.References = "Update", refs
	}
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-7322
//
// A Poller reads a FeedHandler in every format: alerts arrive once, a
// second poll gets 304, linked documents are fetched, an Update joins the
// history chain, and removed or expired alerts leave the feed.
func TestPollerAgainstFeedHandler(t *testing.T) {
	for _, f := range []struct {
		name string
		fmt  capnet.Format
	}{{"atom-embedded", capnet.AtomEmbedded}, {"atom-linked", capnet.AtomLinked}, {"rss", capnet.RSSLinked},
		{"edxl-de-1.0", capnet.EDXLDE10}, {"edxl-de-2.0", capnet.EDXLDE20}} {
		t.Run(f.name, func(t *testing.T) {
			h := &capnet.FeedHandler{Format: f.fmt, ID: "urn:test", Title: "Test feed", Author: "met@example.test"}
			srv := httptest.NewServer(h)
			defer srv.Close()
			first := alertDoc(t, "A-1", "")
			if err := h.Publish(first); err != nil {
				t.Fatal(err)
			}
			hist := cap.NewHistory()
			p := &capnet.Poller{URL: srv.URL + "/feed", UserAgent: "capnet-test", History: hist}
			items, err := p.Poll(context.Background())
			if err != nil || len(items) != 1 || items[0].Alert.Identifier != "A-1" || string(items[0].Raw) != strings.TrimSpace(string(first[strings.Index(string(first), "?>")+2:])) && string(items[0].Raw) != string(first) {
				t.Fatalf("first poll: %d items, %v", len(items), err)
			}
			if items, err := p.Poll(context.Background()); !errors.Is(err, capnet.ErrNotModified) || len(items) != 0 {
				t.Fatalf("second poll: %d items, %v", len(items), err)
			}
			upd := alertDoc(t, "A-2", "met@example.test,A-1,2026-10-12T01:00:00+05:30")
			if err := h.Publish(upd); err != nil {
				t.Fatal(err)
			}
			items, err = p.Poll(context.Background())
			if err != nil || len(items) != 1 || items[0].Alert.Identifier != "A-2" {
				t.Fatalf("after an update: %d items, %v", len(items), err)
			}
			a2, _ := cap.Parse(upd)
			if m := hist.Missing(a2, time.Now()); len(m) != 0 {
				t.Fatalf("history misses %v", m)
			}
			if !h.Remove("met@example.test", "A-1") || h.Prune(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) != 1 {
				t.Fatal("remove and prune")
			}
		})
	}
}

// Covers: SIG-IPE-7322
//
// Linked documents come relative or absolute, and a missing one is
// reported while the rest are delivered.
func TestPollerLinks(t *testing.T) {
	doc := alertDoc(t, "L-1", "")
	mux := http.NewServeMux()
	mux.HandleFunc("/rss", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<rss version="2.0"><channel><title>t</title>`+
			`<item><title>a</title><link>docs/L-1.xml</link><guid>g1</guid></item>`+
			`<item><title>b</title><link>/gone.xml</link><guid>g2</guid></item></channel></rss>`)
	})
	mux.HandleFunc("/docs/L-1.xml", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), cap.MediaType) {
			t.Errorf("Accept %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write(doc)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	p := &capnet.Poller{URL: srv.URL + "/rss"}
	items, err := p.Poll(context.Background())
	if len(items) != 1 || err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("%d items, %v", len(items), err)
	}
}

func signer(t *testing.T) (*cap.Signer, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "capnet.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	s, err := cap.NewSigner(cap.SignSettings{Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})), Certificate: certPEM})
	if err != nil {
		t.Fatal(err)
	}
	return s, certPEM
}

// Covers: SIG-IPE-7323
//
// A Pusher delivers to a Receiver through its checks: token, signature,
// OASIS schema, validation; it retries 503 and stops on a final refusal.
func TestPushToReceiver(t *testing.T) {
	sg, certPEM := signer(t)
	v, err := cap.NewVerifier(cap.VerifySettings{Trusted: []string{certPEM}, Require: true})
	if err != nil {
		t.Fatal(err)
	}
	xv, err := capxsd.Validator()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []capnet.Item
	failing := 2
	rc := &capnet.Receiver{Token: "s3cret", Verifier: v, Schema: []cap.SchemaValidator{xv},
		Deliver: func(_ context.Context, it capnet.Item) error {
			mu.Lock()
			defer mu.Unlock()
			if failing > 0 {
				failing--
				return errors.New("store busy")
			}
			got = append(got, it)
			return nil
		}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	signed, err := sg.Sign(alertDoc(t, "P-1", ""))
	if err != nil {
		t.Fatal(err)
	}
	p := &capnet.Pusher{Token: "s3cret", Backoff: 10 * time.Millisecond}
	if err := p.Push(context.Background(), srv.URL, signed); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Alert.Identifier != "P-1" || string(got[0].Raw) != string(signed) {
		t.Fatalf("delivered %v", got)
	}
	var pe *capnet.PushError
	if err := (&capnet.Pusher{Token: "wrong", Backoff: time.Millisecond}).Push(context.Background(), srv.URL, signed); !errors.As(err, &pe) || pe.Status != http.StatusUnauthorized {
		t.Fatalf("wrong token: %v", err)
	}
	if err := p.Push(context.Background(), srv.URL, alertDoc(t, "P-2", "")); !errors.As(err, &pe) || pe.Status != http.StatusForbidden {
		t.Fatalf("unsigned: %v", err)
	}
	if err := p.Push(context.Background(), srv.URL, []byte("<nope/>")); err == nil {
		t.Fatal("a non-CAP document was pushed")
	}
	// Without a verifier: an alert the OASIS schema refuses is 422.
	rc.Verifier = nil
	bad := strings.Replace(string(alertDoc(t, "P-3", "")), "<status>Actual</status>", "<status>actual</status>", 1)
	if err := p.Push(context.Background(), srv.URL, []byte(bad)); err == nil {
		t.Fatal("a lower-case status was accepted")
	}
}

// Covers: SIG-IPE-7324
//
// SplitStream cuts a byte stream of CAP documents (with or without XML
// declarations, prefixed or not) wherever the reads fall.
func TestSplitStream(t *testing.T) {
	a := string(alertDoc(t, "S-1", ""))
	b := strings.Replace(strings.Replace(string(alertDoc(t, "S-2", "")), "<alert ", "<cap:alert xmlns:cap=\"urn:oasis:names:tc:emergency:cap:1.2\" ", 1), "</alert>", "</cap:alert>", 1)
	b = strings.Replace(b, ` xmlns="urn:oasis:names:tc:emergency:cap:1.2"`, "", 1)
	stream := a + "\n" + b + "  " + a
	var docs []string
	err := capnet.SplitStream(iotest.OneByteReader(strings.NewReader(stream)), 0, func(d []byte) error {
		docs = append(docs, string(d))
		return nil
	})
	if err != nil || len(docs) != 3 {
		t.Fatalf("%d docs, %v", len(docs), err)
	}
	for _, d := range docs {
		if _, err := cap.Parse([]byte(d)); err != nil {
			t.Fatalf("%v\n%s", err, d)
		}
	}
}

// Covers: SIG-IPE-7324
//
// NAADSStream reads alerts and heartbeats from a local stream server and
// reconnects, to the other host, when a connection ends.
func TestNAADSStream(t *testing.T) {
	hb := strings.Replace(string(alertDoc(t, "HB-1", "")), "met@example.test", capnet.NAADSHeartbeatSender, 1)
	serve := func(docs ...string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				for _, d := range docs {
					_, _ = c.Write([]byte(d))
				}
				c.Close()
			}
		}()
		return ln.Addr().String()
	}
	h1 := serve(string(alertDoc(t, "N-1", "")), hb)
	h2 := serve(string(alertDoc(t, "N-2", "")))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	seen := map[string]bool{}
	beats := 0
	s := &capnet.NAADSStream{Hosts: []string{h1, h2}, Backoff: 10 * time.Millisecond,
		Deliver: func(it capnet.Item) {
			mu.Lock()
			seen[it.Alert.Identifier] = true
			if seen["N-1"] && seen["N-2"] && beats > 0 {
				cancel()
			}
			mu.Unlock()
		},
		OnHeartbeat: func(*cap.Alert) { mu.Lock(); beats++; mu.Unlock() }}
	s.Run(ctx)
	if !seen["N-1"] || !seen["N-2"] || beats == 0 {
		t.Fatalf("seen %v, %d heartbeats", seen, beats)
	}
}
