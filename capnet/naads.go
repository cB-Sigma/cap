// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package capnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/cB-Sigma/cap"
)

// NAADS hosts: Canada's National Alert Aggregation and Dissemination
// System streams every alert it carries, and a heartbeat alert about once
// a minute, as CAP documents one after another on a TCP connection.
var NAADSHosts = []string{"streaming1.naad-adna.pelmorex.com:8080", "streaming2.naad-adna.pelmorex.com:8080"}

// NAADSHeartbeatSender is the sender of the NAAD System's heartbeat
// alerts, whose references list the alerts recently sent.
const NAADSHeartbeatSender = "NAADS-Heartbeat"

var alertEnd = regexp.MustCompile(`</(?:[A-Za-z_][\w.\-]*:)?alert\s*>`)

// SplitStream reads CAP documents sent one after another on r (as the
// NAAD System streams them) and calls fn with each, as sent; it returns
// when r ends or fails, or fn returns an error. A document over maxBytes
// (default 4 MiB) is an error.
func SplitStream(r io.Reader, maxBytes int, fn func(doc []byte) error) error {
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	br := bufio.NewReaderSize(r, 64<<10)
	var buf []byte
	chunk := make([]byte, 32<<10)
	for {
		n, err := br.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for {
			loc := alertEnd.FindIndex(buf)
			if loc == nil {
				break
			}
			doc := bytes.TrimSpace(buf[:loc[1]])
			buf = append([]byte(nil), buf[loc[1]:]...)
			if len(doc) > 0 {
				if ferr := fn(doc); ferr != nil {
					return ferr
				}
			}
		}
		if len(bytes.TrimSpace(buf)) > maxBytes {
			return fmt.Errorf("capnet: a streamed document is over %d bytes", maxBytes)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// NAADSStream keeps a connection to the NAAD System's TCP stream (or any
// server that streams CAP documents the same way), alternating between
// hosts and reconnecting when a connection fails or stays silent longer
// than IdleTimeout (heartbeats come about every minute).
type NAADSStream struct {
	// Hosts to connect to, in turn (NAADSHosts when empty).
	Hosts []string
	// Dial makes the connections (a net.Dialer with a 15 s timeout when
	// nil).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// IdleTimeout ends a connection with no data (default 3 min).
	IdleTimeout time.Duration
	// Backoff is the first wait before reconnecting to the same host
	// round (default 2 s, doubling to 2 min).
	Backoff time.Duration
	// Deliver takes each alert other than heartbeats; OnHeartbeat (when
	// set) each heartbeat; Report (when set) each connection error and
	// each document that does not read as CAP.
	Deliver     func(Item)
	OnHeartbeat func(*cap.Alert)
	Report      func(error)
}

func (s *NAADSStream) report(err error) {
	if s.Report != nil && err != nil {
		s.Report(err)
	}
}

// Run connects and reads until ctx ends.
func (s *NAADSStream) Run(ctx context.Context) {
	hosts := s.Hosts
	if len(hosts) == 0 {
		hosts = NAADSHosts
	}
	dial := s.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		dial = d.DialContext
	}
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = 3 * time.Minute
	}
	first := s.Backoff
	if first <= 0 {
		first = 2 * time.Second
	}
	wait := first
	for i := 0; ctx.Err() == nil; i++ {
		host := hosts[i%len(hosts)]
		got, err := s.session(ctx, dial, host, idle)
		if ctx.Err() != nil {
			return
		}
		s.report(fmt.Errorf("capnet: NAADS %s: %w", host, err))
		if got {
			wait = first // the connection worked: start again from the first wait
		}
		if (i+1)%len(hosts) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, 2*time.Minute)
		}
	}
}

// session reads one connection; got says whether any document came.
func (s *NAADSStream) session(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), host string, idle time.Duration) (got bool, err error) {
	conn, err := dial(ctx, "tcp", host)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetReadDeadline(time.Now().Add(idle))
	r := &deadlineReader{conn: conn, idle: idle}
	err = SplitStream(r, 0, func(doc []byte) error {
		got = true
		a, err := cap.Parse(doc)
		if err != nil {
			s.report(fmt.Errorf("capnet: NAADS %s: %w", host, err))
			return nil
		}
		if a.Sender == NAADSHeartbeatSender {
			if s.OnHeartbeat != nil {
				s.OnHeartbeat(a)
			}
			return nil
		}
		if s.Deliver != nil {
			s.Deliver(Item{Alert: a, Raw: doc})
		}
		return nil
	})
	if err == nil {
		err = errors.New("the server closed the connection")
	}
	return got, err
}

// deadlineReader moves the read deadline on after every read.
type deadlineReader struct {
	conn net.Conn
	idle time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	n, err := d.conn.Read(p)
	_ = d.conn.SetReadDeadline(time.Now().Add(d.idle))
	return n, err
}
