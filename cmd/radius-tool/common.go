package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/wxccs/radius/v2/client"
	"github.com/wxccs/radius/v2/dictionary"
	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/protocol"
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
// flags. Each flag value is "type:value" where type is either a numeric
// byte (1..255) or the canonical attribute name from the dictionary (e.g.
// "User-Name"). Names are case-insensitive and may use any dash-cased
// variant ("user-name", "USER-NAME"). The value is encoded using the
// dictionary's ValueType when the type is registered; otherwise the value
// is stored verbatim as a string.
func attrsFromFlags(cmd *cobra.Command) ([]packet.Attribute, error) {
	rawAttrs, err := cmd.Flags().GetStringArray("attr")
	if err != nil {
		return nil, err
	}
	dict := dictionary.Default()
	out := make([]packet.Attribute, 0, len(rawAttrs))
	for _, raw := range rawAttrs {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --attr %q: expected type:value", raw)
		}
		attrType, name, err := resolveAttrType(parts[0])
		if err != nil {
			return nil, err
		}
		// When the type is in the dictionary, defer to packet.NewByName so
		// the value is encoded per ValueType (integer, IP, string, etc.).
		if name != "" {
			a, err := packet.NewByName(dict, name, parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid --attr %q: %w", raw, err)
			}
			out = append(out, a)
			continue
		}
		out = append(out, packet.NewString(attrType, parts[1]))
	}
	return out, nil
}

// resolveAttrType maps a name or numeric string to a RADIUS attribute type.
// Names are looked up in dictionary.Default(); case-insensitive variants
// are normalized to the canonical "User-Name" form before lookup. Returns
// the type byte plus the canonical name (empty when the type was supplied
// numerically and is not registered in the dictionary).
func resolveAttrType(name string) (byte, string, error) {
	if n, err := strconv.Atoi(name); err == nil {
		if n < 1 || n > 255 {
			return 0, "", fmt.Errorf("attribute type %d out of range (1..255)", n)
		}
		t := byte(n)
		// Surface the canonical name when the numeric type is registered.
		if def, ok := dictionary.Default().Lookup(t); ok {
			return t, def.Name, nil
		}
		return t, "", nil
	}
	dict := dictionary.Default()
	if def, ok := dict.LookupName(name); ok {
		return def.Type, def.Name, nil
	}
	if canon := canonicalAttrName(name); canon != name {
		if def, ok := dict.LookupName(canon); ok {
			return def.Type, def.Name, nil
		}
	}
	return 0, "", fmt.Errorf("unknown attribute name %q (use numeric type or dictionary name)", name)
}

// canonicalAttrName normalizes a user-supplied attribute name like
// "user-name" or "USER-NAME" into the canonical "User-Name" form that the
// dictionary registers. Empty segments (from leading/trailing dashes) are
// preserved so obviously malformed input does not silently match.
func canonicalAttrName(s string) string {
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}

// printAttrs pretty-prints attributes for human consumption. Uses the
// dictionary to render attribute names and typed values; unknown types
// fall back to a hex dump.
func printAttrs(attrs []packet.Attribute) {
	if len(attrs) == 0 {
		fmt.Println("  (no attributes)")
		return
	}
	dict := dictionary.Default()
	for _, a := range attrs {
		fmt.Printf("  %s\n", packet.FormatAttribute(a, dict))
	}
}

// ensureTimeoutPositive guards against zero/negative --timeout values
// which would cause ctx to be immediately canceled.
func ensureTimeoutPositive() error {
	if t := viper.GetDuration("timeout"); t <= 0 {
		return fmt.Errorf("--timeout must be positive, got %v", t)
	}
	return nil
}
