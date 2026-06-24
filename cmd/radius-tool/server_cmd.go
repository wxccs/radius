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
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/server"
	"github.com/wxccs/radius/types"
)

// echoAccessHandler replies with Access-Accept for any Access-Request.
// Useful for smoke-testing the client without a real auth backend.
func echoAccessHandler(_ context.Context, req *server.Request) (*packet.Packet, error) {
	if req.Code != types.AccessRequest {
		return nil, nil
	}
	return &packet.Packet{
		Code:          types.AccessAccept,
		Identifier:    req.Identifier,
		Authenticator: req.Authenticator,
		Attributes: []packet.Attribute{
			packet.NewString(types.AttrReplyMessage, "accepted"),
		},
	}, nil
}

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run a minimal echo RADIUS server",
		Long: `Run a RADIUS server that replies to Access-Request with Access-Accept.

Intended for smoke testing and local development. NOT for production use:
the server does not consult a user database, accepts any shared secret,
and does not perform rate limiting or duplicate detection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			bind, _ := cmd.Flags().GetString("bind")
			network, _ := cmd.Flags().GetString("network")
			secret := []byte(cmd.Flags().Lookup("secret").Value.String())

			host, portStr, err := net.SplitHostPort(bind)
			if err != nil {
				return fmt.Errorf("invalid --bind %q: %w", bind, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("invalid bind IP %q", host)
			}
			port, err := net.LookupPort("network", portStr)
			if err != nil {
				return fmt.Errorf("invalid port %q: %w", portStr, err)
			}

			// Pick transport based on --network. The default is udp.
			transportMode := network
			if transportMode == "" {
				transportMode = "udp"
			}

			ctx, cancel := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer cancel()

			switch transportMode {
			case "udp", "udp4", "udp6":
				srv, err := server.NewUDPServer(transportMode,
					&net.UDPAddr{IP: ip, Port: port},
					server.HandlerFunc(echoAccessHandler),
					server.StaticSecret(secret))
				if err != nil {
					return err
				}
				defer func() { _ = srv.Close() }()
				fmt.Printf("RADIUS UDP server listening on %s (secret=%q)\n",
					srv.LocalAddr(), string(secret))
				return srv.Serve(ctx)
			case "tcp", "tcp4", "tcp6":
				srv, err := server.NewTCPServer(transportMode,
					&net.TCPAddr{IP: ip, Port: port},
					server.HandlerFunc(echoAccessHandler),
					server.StaticSecret(secret))
				if err != nil {
					return err
				}
				defer func() { _ = srv.Close() }()
				fmt.Printf("RADIUS TCP server listening on %s (secret=%q)\n",
					srv.LocalAddr(), string(secret))
				return srv.Serve(ctx)
			default:
				return fmt.Errorf("unsupported --network %q", transportMode)
			}
		},
	}
	cmd.Flags().String("bind", "127.0.0.1:1812", "listen address (host:port)")
	// --network and --secret are inherited from the root persistent flags,
	// so we only override the default for server mode if the user did not
	// set them. We do not re-register them here to avoid cobra's "flag
	// already defined" error.
	return cmd
}
