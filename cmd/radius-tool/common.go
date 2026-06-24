// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Daniel Wu
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

package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/wxccs/radius/client"
	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/types"
)

// resolveServerAddr parses host:port into a UDP and a TCP address.
// The same string works for both transports in IPv4/IPv6 cases.
func resolveServerAddr(hostport string) (*net.UDPAddr, *net.TCPAddr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid --server %q: %w", hostport, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid port in --server %q: %w", hostport, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("failed to resolve %q: %w", host, err)
		}
		ip = ips[0]
	}
	udpAddr := &net.UDPAddr{IP: ip, Port: port}
	tcpAddr := &net.TCPAddr{IP: ip, Port: port}
	return udpAddr, tcpAddr, nil
}

// newClient constructs a UDP or TCP client per the global config.
func newClient() (*protocol.Client, func() error, error) {
	udpAddr, tcpAddr, err := resolveServerAddr(viper.GetString("server"))
	if err != nil {
		return nil, nil, err
	}
	secret := []byte(viper.GetString("secret"))
	if len(secret) == 0 {
		return nil, nil, fmt.Errorf("--secret is required for client modes")
	}
	cfg := client.Config{Timeout: viper.GetDuration("timeout")}

	switch strings.ToLower(viper.GetString("network")) {
	case "udp", "udp4", "udp6":
		c, err := client.NewUDPClient(udpAddr, secret, cfg)
		if err != nil {
			return nil, nil, err
		}
		return c.Client, c.Close, nil
	case "tcp", "tcp4", "tcp6":
		c, err := client.NewTCPClient(tcpAddr, secret, cfg)
		if err != nil {
			return nil, nil, err
		}
		return c.Client, c.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported --network %q (use udp or tcp)", viper.GetString("network"))
	}
}

// callCtx returns a context bounded by the global --timeout.
func callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), viper.GetDuration("timeout"))
}

// attrsFromFlags builds a packet.Attribute slice from repeated --attr
// flags. Each flag value is "type:value" where type is a numeric or a
// well-known name (e.g. "User-Name") and value is parsed as a string,
// integer (decimal), or IP address based on heuristics.
func attrsFromFlags(cmd *cobra.Command) ([]packet.Attribute, error) {
	rawAttrs, err := cmd.Flags().GetStringArray("attr")
	if err != nil {
		return nil, err
	}
	out := make([]packet.Attribute, 0, len(rawAttrs))
	for _, raw := range rawAttrs {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --attr %q: expected type:value", raw)
		}
		attrType, err := resolveAttrType(parts[0])
		if err != nil {
			return nil, err
		}
		value, err := encodeAttrValue(attrType, parts[1])
		if err != nil {
			return nil, err
		}
		out = append(out, packet.Attribute{Type: attrType, Value: value})
	}
	return out, nil
}

// resolveAttrType maps a name or numeric string to a RADIUS attribute type.
// A small subset of common names is supported; numeric values pass through.
func resolveAttrType(name string) (byte, error) {
	if n, err := strconv.Atoi(name); err == nil {
		if n < 1 || n > 255 {
			return 0, fmt.Errorf("attribute type %d out of range (1..255)", n)
		}
		return byte(n), nil
	}
	switch strings.ToLower(name) {
	case "user-name":
		return types.AttrUserName, nil
	case "user-password":
		return types.AttrUserPassword, nil
	case "nas-ip-address":
		return types.AttrNASIPAddress, nil
	case "nas-port":
		return types.AttrNASPort, nil
	case "service-type":
		return types.AttrServiceType, nil
	case "nas-identifier":
		return types.AttrNASIdentifier, nil
	case "acct-status-type":
		return types.AttrAcctStatusType, nil
	case "acct-session-id":
		return types.AttrAcctSessionID, nil
	case "acct-session-time":
		return types.AttrAcctSessionTime, nil
	case "session-timeout":
		return types.AttrSessionTimeout, nil
	case "reply-message":
		return types.AttrReplyMessage, nil
	case "state":
		return types.AttrState, nil
	case "message-authenticator":
		return types.AttrMessageAuthenticator, nil
	case "error-cause":
		return types.AttrErrorCause, nil
	default:
		return 0, fmt.Errorf("unknown attribute name %q (use numeric type)", name)
	}
}

// encodeAttrValue encodes a string value into the wire format for the
// attribute type. Integers and IP addresses are detected by type;
// everything else is treated as a string (octets).
func encodeAttrValue(attrType byte, value string) ([]byte, error) {
	switch attrType {
	case types.AttrNASIPAddress, types.AttrLoginIPHost:
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP for attribute %d: %q", attrType, value)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("IPv6 not supported for attribute %d", attrType)
		}
		return ip4, nil
	case types.AttrNASPort, types.AttrServiceType, types.AttrAcctStatusType,
		types.AttrAcctSessionTime, types.AttrSessionTimeout, types.AttrErrorCause:
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid integer for attribute %d: %w", attrType, err)
		}
		return packet.NewInteger(attrType, uint32(n)).Value, nil
	default:
		return []byte(value), nil
	}
}

// printAttrs pretty-prints attributes for human consumption.
func printAttrs(attrs []packet.Attribute) {
	if len(attrs) == 0 {
		fmt.Println("  (no attributes)")
		return
	}
	for _, a := range attrs {
		fmt.Printf("  Attr %d = %s\n", a.Type, formatAttrValue(a))
	}
}

// formatAttrValue renders an attribute value as a string, guessing the
// type by length and content. IPv4 (4 bytes) is rendered as an IP;
// otherwise printable strings are shown as quoted text, and everything
// else falls back to hex.
func formatAttrValue(a packet.Attribute) string {
	switch len(a.Value) {
	case 4:
		if a.Type == types.AttrNASIPAddress || a.Type == types.AttrLoginIPHost {
			return net.IP(a.Value).String()
		}
		if n, err := a.Integer(); err == nil {
			return strconv.FormatUint(uint64(n), 10)
		}
	case 6:
		if n, err := a.Integer(); err == nil {
			return strconv.FormatUint(uint64(n), 10)
		}
	}
	if s, err := a.String(); err == nil && isPrintable(a.Value) {
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%x", a.Value)
}

// isPrintable reports whether b is a reasonable printable ASCII string.
func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// ensureTimeoutPositive guards against zero/negative --timeout values
// which would cause ctx to be immediately canceled.
func ensureTimeoutPositive() error {
	if t := viper.GetDuration("timeout"); t <= 0 {
		return fmt.Errorf("--timeout must be positive, got %v", t)
	}
	return nil
}
