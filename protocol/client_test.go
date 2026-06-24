// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 wxccs
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package protocol

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	radiuserrors "github.com/wxccs/radius/errors"
	radiuslog "github.com/wxccs/radius/log"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/types"
)

// fakeTransport is a test Transport that records the bytes sent and
// returns a programmable reply. It is safe for concurrent use.
type fakeTransport struct {
	mu       sync.Mutex
	sent     [][]byte
	replyFn  func(raw []byte) ([]byte, error)
	closed   atomic.Bool
	closeErr error
}

func (t *fakeTransport) Exchange(ctx context.Context, raw []byte) ([]byte, error) {
	if t.closed.Load() {
		return nil, radiuserrors.ErrConnClosed
	}
	t.mu.Lock()
	t.sent = append(t.sent, append([]byte(nil), raw...))
	fn := t.replyFn
	t.mu.Unlock()
	if fn == nil {
		return nil, errors.New("no reply configured")
	}
	return fn(raw)
}

func (t *fakeTransport) Close() error {
	t.closed.Store(true)
	return t.closeErr
}

// buildReply builds a RADIUS reply packet for the given request.
func buildReply(t *testing.T, reqRaw []byte, code types.Code, reqAuth [16]byte, secret []byte, attrs []packet.Attribute) []byte {
	t.Helper()
	pkt := &packet.Packet{
		Code:          code,
		Identifier:    reqRaw[1],
		Authenticator: reqAuth,
		Attributes:    attrs,
	}
	raw, err := pkt.Marshal(secret)
	require.NoError(t, err)
	return raw
}

// extractRequestAuth returns the 16-byte Authenticator field from a
// marshaled request. For Access-Request this is the caller-supplied random
// value; for other codes it is the MD5-derived Request Authenticator that
// packet.Marshal wrote.
func extractRequestAuth(reqRaw []byte) [16]byte {
	var a [16]byte
	copy(a[:], reqRaw[4:20])
	return a
}

func TestClient_Authenticate_PAP_Accept(t *testing.T) {
	secret := []byte("pap-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, []packet.Attribute{
			packet.NewInteger(types.AttrSessionTimeout, 3600),
		}), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "alice"),
			packet.NewString(types.AttrUserPassword, "hunter2"),
			packet.NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 1)),
		},
		Method: AuthPAP,
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
	require.Len(t, tr.sent, 1)

	// Verify the sent packet is a well-formed Access-Request.
	sent := tr.sent[0]
	assert.Equal(t, byte(types.AccessRequest), sent[0])
	require.Greater(t, len(sent), 20)
	// User-Password attribute should be encrypted (not "hunter2" in cleartext).
	p := &packet.Packet{}
	require.NoError(t, p.Unmarshal(sent, secret))
	pwAttr, ok := p.GetOne(types.AttrUserPassword)
	require.True(t, ok)
	assert.NotContains(t, string(pwAttr.Value), "hunter2")
}

func TestClient_Authenticate_Reject(t *testing.T) {
	secret := []byte("reject-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessReject, reqAuth, secret, []packet.Attribute{
			packet.NewString(types.AttrReplyMessage, "denied"),
		}), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "bob"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessReject, resp.Code)
}

func TestClient_Authenticate_Challenge(t *testing.T) {
	secret := []byte("challenge-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessChallenge, reqAuth, secret, []packet.Attribute{
			packet.NewString(types.AttrState, "state-token"),
			packet.NewString(types.AttrReplyMessage, "enter OTP"),
		}), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "carol")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessChallenge, resp.Code)
}

func TestClient_Authenticate_EAP_AddsMessageAuthenticator(t *testing.T) {
	secret := []byte("eap-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		// Verify the outgoing packet contains Message-Authenticator.
		p := &packet.Packet{}
		require.NoError(t, p.Unmarshal(raw, secret))
		_, ok := p.GetOne(types.AttrMessageAuthenticator)
		require.True(t, ok, "EAP Access-Request must carry Message-Authenticator")
		require.NoError(t, packet.VerifyMessageAuthenticator(raw, secret))

		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, []packet.Attribute{
			packet.NewOctets(types.AttrMessageAuthenticator, make([]byte, 16)),
		}), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserName, "dave"),
			packet.NewOctets(types.AttrEAPMessage, []byte{0x01, 0x00, 0x00, 0x05, 0x01}),
		},
		Method: AuthEAP,
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
}

func TestClient_Authenticate_RetransmitsOnError(t *testing.T) {
	secret := []byte("retry-secret")
	tr := &fakeTransport{}
	var calls atomic.Int32
	tr.replyFn = func(raw []byte) ([]byte, error) {
		n := calls.Add(1)
		if n < 2 {
			return nil, radiuserrors.ErrTimeout
		}
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 3, Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Jitter: 0,
	}))

	resp, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.AccessAccept, resp.Code)
	assert.Equal(t, int32(2), calls.Load(), "expected one timeout then one success")
	require.Len(t, tr.sent, 2, "expected two transmissions")
	// Both transmissions must use the same Identifier and Request Authenticator.
	assert.Equal(t, tr.sent[0][1], tr.sent[1][1], "Identifier must be reused across retransmissions")
	assert.Equal(t, tr.sent[0][4:20], tr.sent[1][4:20], "Request Authenticator must be reused across retransmissions")
}

func TestClient_Authenticate_NoResponseAfterRetries(t *testing.T) {
	secret := []byte("no-reply-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		return nil, radiuserrors.ErrTimeout
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 2, Initial: 5 * time.Millisecond, Max: 10 * time.Millisecond, Jitter: 0,
	}))

	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	assert.ErrorIs(t, err, radiuserrors.ErrTimeout)
	require.Len(t, tr.sent, 2, "expected exactly MaxAttempts transmissions")
}

func TestClient_Authenticate_DiscardsMismatchedIdentifier(t *testing.T) {
	secret := []byte("mid-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		reply := buildReply(t, raw, types.AccessAccept, reqAuth, secret, nil)
		// Flip the Identifier so the reply looks like it's for a different request.
		reply[1] ^= 0xff
		return reply, nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 3, Initial: 5 * time.Millisecond, Max: 10 * time.Millisecond, Jitter: 0,
	}))

	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	// After discarding the bad-ID reply, we retransmit and again get a bad-ID
	// reply, so all attempts are exhausted and we surface the last error.
	require.Error(t, err)
	require.Len(t, tr.sent, 3, "bad-ID reply should not count as success; all attempts used")
}

func TestClient_Authenticate_ContextCanceled(t *testing.T) {
	secret := []byte("cancel-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		return nil, radiuserrors.ErrTimeout
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 100, Initial: 100 * time.Millisecond, Max: 200 * time.Millisecond, Jitter: 0,
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Authenticate(ctx, &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClient_Authenticate_UnexpectedReplyCode(t *testing.T) {
	secret := []byte("unexpected-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		// Server replies with Accounting-Response to an Access-Request — wrong code.
		return buildReply(t, raw, types.AccountingResponse, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	assert.ErrorIs(t, err, ErrUnexpectedReply)
}

func TestClient_Account(t *testing.T) {
	secret := []byte("acct-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccountingResponse, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.Account(context.Background(), &AccountingRequest{
		Attributes: []packet.Attribute{
			packet.NewInteger(types.AttrAcctStatusType, 1),
			packet.NewString(types.AttrAcctSessionID, "sess-1"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, byte(tr.sent[0][1]), resp.Identifier)

	// The sent packet must be a valid Accounting-Request that Unmarshal
	// (with the correct secret) accepts.
	p := &packet.Packet{}
	require.NoError(t, p.Unmarshal(tr.sent[0], secret))
	assert.Equal(t, types.AccountingRequest, p.Code)
}

func TestClient_SendCoA(t *testing.T) {
	secret := []byte("coa-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		// Verify the outgoing CoA-Request carries Message-Authenticator.
		p := &packet.Packet{}
		require.NoError(t, p.Unmarshal(raw, secret))
		_, ok := p.GetOne(types.AttrMessageAuthenticator)
		require.True(t, ok, "CoA-Request must carry Message-Authenticator (RFC 5176 §3.4)")
		require.NoError(t, packet.VerifyMessageAuthenticator(raw, secret))

		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.CoAACK, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.SendCoA(context.Background(), &CoARequest{
		Attributes: []packet.Attribute{
			packet.NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 1)),
			packet.NewString(types.AttrAcctSessionID, "sess-coa"),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, byte(tr.sent[0][1]), resp.Identifier)
}

func TestClient_SendCoA_NAK_WithErrorCode(t *testing.T) {
	secret := []byte("coa-nak-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.CoANAK, reqAuth, secret, []packet.Attribute{
			packet.NewInteger(types.AttrErrorCause, 405), // Missing Attribute
		}), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.SendCoA(context.Background(), &CoARequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrAcctSessionID, "sess-x")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.CoANAK, resp.Code)
	require.Len(t, resp.Attributes, 1)
}

func TestClient_SendDisconnect(t *testing.T) {
	secret := []byte("dm-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		p := &packet.Packet{}
		require.NoError(t, p.Unmarshal(raw, secret))
		_, ok := p.GetOne(types.AttrMessageAuthenticator)
		require.True(t, ok, "Disconnect-Request must carry Message-Authenticator (RFC 5176 §3.4)")

		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.DisconnectACK, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	resp, err := c.SendDisconnect(context.Background(), &DisconnectRequest{
		Attributes: []packet.Attribute{
			packet.NewIPAddr(types.AttrNASIPAddress, net.IPv4(10, 0, 0, 2)),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, byte(tr.sent[0][1]), resp.Identifier)
}

func TestClient_Close(t *testing.T) {
	tr := &fakeTransport{}
	c := NewClient(tr, nil)
	require.NoError(t, c.Close())
	assert.True(t, tr.closed.Load())
}

func TestClient_IdentifierPool_ConcurrentRequestsUseDistinctIDs(t *testing.T) {
	secret := []byte("concurrent-secret")
	tr := &fakeTransport{}
	seenIDs := make(map[byte]bool)
	var mu sync.Mutex
	tr.replyFn = func(raw []byte) ([]byte, error) {
		mu.Lock()
		id := raw[1]
		assert.False(t, seenIDs[id], "concurrent requests must not share an Identifier")
		seenIDs[id] = true
		mu.Unlock()

		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := c.Authenticate(context.Background(), &AccessRequest{
				Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
			})
			assert.NoError(t, err)
		})
	}
	wg.Wait()
	assert.Len(t, seenIDs, 16)
}

func TestClient_Options(t *testing.T) {
	t.Run("WithIdentifierPool", func(t *testing.T) {
		pool := NewIdentifierPool()
		c := NewClient(&fakeTransport{}, []byte("s"), WithIdentifierPool(pool))
		assert.Same(t, pool, c.idPool)
	})

	t.Run("WithLogger_NilFallsBackToNop", func(t *testing.T) {
		c := NewClient(&fakeTransport{}, []byte("s"), WithLogger(nil))
		assert.Equal(t, radiuslog.NopLogger{}, c.log)
	})

	t.Run("WithLogger_Real", func(t *testing.T) {
		c := NewClient(&fakeTransport{}, []byte("s"), WithLogger(radiuslog.NopLogger{}))
		assert.NotNil(t, c.log)
	})
}

func TestClient_Authenticate_MarshalFailure(t *testing.T) {
	tr := &fakeTransport{}
	c := NewClient(tr, []byte("s"), WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	// Invalid code path is enforced by packet layer, but we can force a marshal
	// failure by passing a User-Password attribute that is too long (handled
	// by crypto.EncryptUserPassword). The Access-Request path will fail.
	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrUserPassword, string(make([]byte, 200))),
		},
	})
	assert.Error(t, err)
	assert.Empty(t, tr.sent, "no packet should have been sent on marshal failure")
}

func TestClient_Authenticate_PoolExhaustion(t *testing.T) {
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		// Hang forever; the test will cancel the context.
		time.Sleep(time.Hour)
		return nil, errors.New("unreachable")
	}
	c := NewClient(tr, []byte("s"), WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 1, Initial: time.Hour, Max: time.Hour, Jitter: 0,
	}))

	// Acquire all 256 identifiers so the next call must block.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	for range 256 {
		_, err := c.idPool.Acquire(ctx1)
		require.NoError(t, err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	_, err := c.Authenticate(ctx2, &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	assert.ErrorIs(t, err, ErrIdentifierExhausted)
}

func TestClient_Authenticate_CallerSuppliedAuthenticator(t *testing.T) {
	secret := []byte("fixed-auth-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		// Caller-supplied authenticator must appear on the wire.
		var got [16]byte
		copy(got[:], raw[4:20])
		assert.Equal(t, [16]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}, got)
		return buildReply(t, raw, types.AccessAccept, got, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))

	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Authenticator: [16]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
			0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89},
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.NoError(t, err)
}

func TestClient_Authenticate_RandomAuthenticatorGenerationFailure(t *testing.T) {
	// We cannot easily force rand.Read to fail. Instead, exercise the
	// zero-authenticator branch by NOT supplying one and verifying the
	// outgoing packet has a non-zero authenticator.
	secret := []byte("auto-auth-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		var auth [16]byte
		copy(auth[:], raw[4:20])
		assert.NotEqual(t, [16]byte{}, auth, "authenticator must be auto-generated when not supplied")
		return buildReply(t, raw, types.AccessAccept, auth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.NoError(t, err)
}

func TestClient_Account_UnexpectedReplyCode(t *testing.T) {
	secret := []byte("acct-unexpected-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	_, err := c.Account(context.Background(), &AccountingRequest{
		Attributes: []packet.Attribute{packet.NewInteger(types.AttrAcctStatusType, 1)},
	})
	assert.ErrorIs(t, err, ErrUnexpectedReply)
}

func TestClient_Account_MarshalFailure(t *testing.T) {
	tr := &fakeTransport{}
	c := NewClient(tr, []byte("s"), WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	_, err := c.Account(context.Background(), &AccountingRequest{
		Attributes: []packet.Attribute{
			{Type: types.AttrUserName, Value: make([]byte, 254)}, // value too long
		},
	})
	assert.Error(t, err)
	assert.Empty(t, tr.sent)
}

func TestClient_SendCoA_UnexpectedReplyCode(t *testing.T) {
	secret := []byte("coa-unexpected-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	_, err := c.SendCoA(context.Background(), &CoARequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrAcctSessionID, "x")},
	})
	assert.ErrorIs(t, err, ErrUnexpectedReply)
}

func TestClient_SendDisconnect_UnexpectedReplyCode(t *testing.T) {
	secret := []byte("dm-unexpected-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.AccessAccept, reqAuth, secret, nil), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	_, err := c.SendDisconnect(context.Background(), &DisconnectRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrAcctSessionID, "x")},
	})
	assert.ErrorIs(t, err, ErrUnexpectedReply)
}

func TestClient_SendDisconnect_NAK(t *testing.T) {
	secret := []byte("dm-nak-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		reqAuth := extractRequestAuth(raw)
		return buildReply(t, raw, types.DisconnectNAK, reqAuth, secret, []packet.Attribute{
			packet.NewInteger(types.AttrErrorCause, 503), // NAS Identification Missing
		}), nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{MaxAttempts: 1}))
	resp, err := c.SendDisconnect(context.Background(), &DisconnectRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrAcctSessionID, "x")},
	})
	require.NoError(t, err)
	assert.Equal(t, types.DisconnectNAK, resp.Code)
}

func TestClient_Authenticate_RetransmitCanceledDuringDelay(t *testing.T) {
	secret := []byte("cancel-delay-secret")
	tr := &fakeTransport{}
	tr.replyFn = func(raw []byte) ([]byte, error) {
		return nil, radiuserrors.ErrTimeout
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 5, Initial: time.Hour, Max: time.Hour, Jitter: 0,
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := c.Authenticate(ctx, &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClient_Authenticate_VerificationFailureRetries(t *testing.T) {
	secret := []byte("verify-retry-secret")
	tr := &fakeTransport{}
	var calls atomic.Int32
	tr.replyFn = func(raw []byte) ([]byte, error) {
		calls.Add(1)
		reqAuth := extractRequestAuth(raw)
		reply := buildReply(t, raw, types.AccessAccept, reqAuth, secret, []packet.Attribute{
			packet.NewInteger(types.AttrServiceType, 1),
		})
		// Tamper with the body (Service-Type attribute value at offset 22).
		reply[22] ^= 0xff
		return reply, nil
	}
	c := NewClient(tr, secret, WithRetransmitPolicy(RetransmitPolicy{
		MaxAttempts: 2, Initial: 5 * time.Millisecond, Max: 10 * time.Millisecond, Jitter: 0,
	}))
	_, err := c.Authenticate(context.Background(), &AccessRequest{
		Attributes: []packet.Attribute{packet.NewString(types.AttrUserName, "alice")},
	})
	require.Error(t, err)
	assert.Equal(t, int32(2), calls.Load(), "verification failure should trigger retransmission")
}

func TestNewAccessRequestAuthenticator_Distinct(t *testing.T) {
	a1, err := NewAccessRequestAuthenticator()
	require.NoError(t, err)
	a2, err := NewAccessRequestAuthenticator()
	require.NoError(t, err)
	assert.NotEqual(t, a1, a2)
}
