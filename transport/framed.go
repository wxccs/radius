package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	radiuserrors "github.com/wxccs/radius/v2/errors"
	radiuslog "github.com/wxccs/radius/v2/log"
	"github.com/wxccs/radius/v2/types"
)

// readFramedStream reads one Length-framed RADIUS packet from a byte-
// stream connection (TCP or TLS). The 4-byte RADIUS header is read
// first; the Length field at offset 2..3 is then used to read the
// remaining payload. The returned slice is a private copy that
// includes the header.
//
// Byte-stream semantics: io.ReadFull is used because Read may return
// partial data. DO NOT use this for DTLS — DTLS is message-oriented
// and pion's Read returns the full decrypted record in one call,
// erroring with errBufferTooSmall if the caller's buffer is smaller
// than the record. Use readFramedMessage for DTLS.
func readFramedStream(c net.Conn, ctx context.Context, log radiuslog.Logger) ([]byte, error) {
	if err := applyReadDeadline(c, ctx); err != nil {
		if isClosed(err) {
			return nil, radiuserrors.ErrConnClosed
		}
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return nil, mapReadErr(err, ctx)
	}
	length, err := validateRadiusLength(header, log)
	if err != nil {
		return nil, err
	}
	out := make([]byte, int(length))
	copy(out[0:4], header[:])
	if _, err := io.ReadFull(c, out[4:]); err != nil {
		log.Warn("short read on payload", "error", err)
		return nil, mapReadErr(err, ctx)
	}
	log.Debug("read packet",
		"length", int(length),
		"code", int(header[0]))
	return out, nil
}

// readFramedMessage reads one Length-framed RADIUS packet from a
// message-oriented connection (DTLS over UDP). One Read call returns
// the full decrypted DTLS record; we validate the embedded RADIUS
// Length field and return a copy of the first Length bytes.
//
// Message-oriented semantics: the buffer must be large enough to hold
// the entire record, otherwise pion returns errBufferTooSmall and
// leaves the record unconsumed.
func readFramedMessage(c net.Conn, ctx context.Context, log radiuslog.Logger) ([]byte, error) {
	if err := applyReadDeadline(c, ctx); err != nil {
		if isClosed(err) {
			return nil, radiuserrors.ErrConnClosed
		}
		return nil, err
	}
	buf := make([]byte, types.PacketMaxLengthRFC2866)
	n, err := c.Read(buf)
	if err != nil {
		return nil, mapReadErr(err, ctx)
	}
	if n < 4 {
		log.Warn("short read on header", "n", n)
		return nil, radiuserrors.ErrMalformedPacket
	}
	var header [4]byte
	copy(header[:], buf[:4])
	length, err := validateRadiusLength(header, log)
	if err != nil {
		return nil, err
	}
	if int(length) > n {
		log.Warn("declared length exceeds received bytes",
			"declared", int(length),
			"received", n)
		return nil, radiuserrors.ErrMalformedPacket
	}
	out := make([]byte, int(length))
	copy(out, buf[:length])
	log.Debug("read packet",
		"length", int(length),
		"code", int(header[0]))
	return out, nil
}

// validateRadiusLength parses the 2-byte Length field at offset 2..3 of
// the RADIUS header and enforces the per-code bounds defined by
// RFC 2865 (auth, max 4096) and RFC 2866 (accounting, max 4095).
func validateRadiusLength(header [4]byte, log radiuslog.Logger) (uint16, error) {
	length := binary.BigEndian.Uint16(header[2:4])
	if int(length) < types.PacketMinLength {
		log.Warn("malformed: length below minimum", "length", int(length))
		return 0, radiuserrors.ErrMalformedPacket
	}
	maxLen := types.PacketMaxLengthRFC2865
	if isAccountingCode(types.Code(header[0])) {
		maxLen = types.PacketMaxLengthRFC2866
	}
	if int(length) > maxLen {
		log.Warn("malformed: length above maximum",
			"length", int(length),
			"max", maxLen)
		return 0, radiuserrors.ErrMalformedPacket
	}
	return length, nil
}

// writeFramedPacket writes one RADIUS packet to c. The write is
// serialized by writeMu so concurrent callers do not interleave bytes
// on the wire.
func writeFramedPacket(c io.Writer, raw []byte, writeMu *sync.Mutex, log radiuslog.Logger) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	n, err := c.Write(raw)
	if err != nil {
		if isClosed(err) {
			return radiuserrors.ErrConnClosed
		}
		return err
	}
	if n != len(raw) {
		log.Warn("short write",
			"written", n,
			"expected", len(raw))
		return radiuserrors.ErrShortBuffer
	}
	log.Debug("sent packet", "length", n)
	return nil
}

// applyReadDeadline translates the context deadline into a
// SetReadDeadline call on c. A context without a deadline clears any
// prior deadline.
func applyReadDeadline(c net.Conn, ctx context.Context) error {
	if dl, ok := ctx.Deadline(); ok {
		return c.SetReadDeadline(dl)
	}
	return c.SetReadDeadline(time.Time{})
}
