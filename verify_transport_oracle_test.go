// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type countingVerifier struct{ calls int }

func (v *countingVerifier) Verify(_ context.Context, req VerifyRequest, region, node string) VerifyResponse {
	v.calls++
	return VerifyResponse{Nonce: req.Nonce, Reachable: true, ObserverNode: node, ObserverRegion: region}
}

func verifyPost(h http.Handler, body []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/reach/verify", bytes.NewReader(body)))
	return rec
}

// The verify handler serves only a caller its mount authorizes, and reads no
// body past its bound.
func TestServeVerifyHTTPServesOnlyAnAuthorizedCaller(t *testing.T) {
	body, _ := json.Marshal(VerifyRequest{Nonce: []byte("n"), TargetAddr: Address{Proto: "udp", Host: "203.0.113.5", Port: 9000}})
	v := &countingVerifier{}
	for name, authorize := range map[string]func(*http.Request) error{
		"no authorizer":         nil,
		"a refusing authorizer": func(*http.Request) error { return errors.New("not a peer") },
	} {
		if rec := verifyPost(ServeVerifyHTTP(v, "iad", "obs", authorize), body); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
	}
	if v.calls != 0 {
		t.Fatalf("the verifier ran %d times for unauthorized callers", v.calls)
	}
	ok := ServeVerifyHTTP(v, "iad", "obs", func(*http.Request) error { return nil })
	if rec := verifyPost(ok, body); rec.Code != http.StatusOK || v.calls != 1 {
		t.Fatalf("an authorized caller: status %d, calls %d; want 200 and one probe", rec.Code, v.calls)
	}
	big := append([]byte(`{"n":"`), bytes.Repeat([]byte("a"), maxVerifyBodyBytes)...)
	if rec := verifyPost(ok, append(big, '"', '}')); rec.Code != http.StatusBadRequest || v.calls != 1 {
		t.Fatalf("an oversize body: status %d, calls %d; want 400 and no probe", rec.Code, v.calls)
	}
}

// DefaultVerifier dials only a public unicast IP literal over UDP or TCP: a
// request naming the observer's loopback, private network, link-local metadata
// address, a host name or another protocol reaches nothing, and a dial failure
// answers no error text.
func TestDefaultVerifierDialsOnlyAPublicAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Errorf("ln.Close: %v", err)
		}
	}()
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			if err := c.Close(); err != nil {
				t.Errorf("c.Close: %v", err)
			}
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	v := DefaultVerifier{Timeout: 200 * time.Millisecond}
	for _, a := range []Address{
		{Proto: "tcp", Host: "127.0.0.1", Port: port},
		{Proto: "tcp", Host: "::1", Port: port},
		{Proto: "tcp", Host: "localhost", Port: port},
		{Proto: "tcp", Host: "10.0.0.1", Port: 80},
		{Proto: "tcp", Host: "fdaa::1", Port: 80},
		{Proto: "tcp", Host: "169.254.169.254", Port: 80},
		{Proto: "tcp", Host: "0.0.0.0", Port: port},
		{Proto: "udp", Host: "224.0.0.1", Port: 80},
		{Proto: "unix", Host: "203.0.113.5", Port: 80},
		{Proto: "tcp", Host: "203.0.113.5", Port: 0},
	} {
		got := v.Verify(context.Background(), VerifyRequest{TargetAddr: a}, "iad", "obs")
		if got.Reachable || got.Reason != VerifyReasonRefusedTarget {
			t.Errorf("target %s %s: %+v; want refused", a.Proto, net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))), got)
		}
	}
	select {
	case <-accepted:
		t.Fatal("the verifier dialled the observer's own loopback listener")
	case <-time.After(100 * time.Millisecond):
	}
	got := v.Verify(context.Background(), VerifyRequest{TargetAddr: Address{Proto: "tcp", Host: "192.0.2.1", Port: 9}}, "iad", "obs")
	if got.Reachable || got.Reason != VerifyReasonUnreachable || strings.Contains(got.Reason, "dial") {
		t.Fatalf("a dial that fails: %+v; want unreachable with no error text", got)
	}
}
