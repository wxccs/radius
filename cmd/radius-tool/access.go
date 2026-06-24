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

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/types"
)

func newAccessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Send an Access-Request",
		Long:  "Send a RADIUS Access-Request and print the Access-Accept/-Reject/-Challenge reply.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureTimeoutPositive(); err != nil {
				return err
			}
			attrs, err := attrsFromFlags(cmd)
			if err != nil {
				return err
			}
			// If User-Password is provided via --password, inject it as an
			// attribute so the protocol layer can encrypt it.
			if pw, _ := cmd.Flags().GetString("password"); pw != "" {
				attrs = append(attrs, packet.NewString(types.AttrUserPassword, pw))
			}
			method := protocol.AuthPAP
			if eap, _ := cmd.Flags().GetBool("eap"); eap {
				method = protocol.AuthEAP
			}

			c, closeFn, err := newClient()
			if err != nil {
				return err
			}
			defer closeFn()

			ctx, cancel := callCtx()
			defer cancel()

			resp, err := c.Authenticate(ctx, &protocol.AccessRequest{
				Attributes: attrs,
				Method:     method,
			})
			if err != nil {
				return fmt.Errorf("access-request failed: %w", err)
			}
			fmt.Printf("Reply: %s (id=%d)\n", resp.Code, resp.Identifier)
			printAttrs(resp.Attributes)
			return nil
		},
	}
	cmd.Flags().String("password", "", "User-Password (PAP); encrypted before sending")
	cmd.Flags().Bool("eap", false, "use EAP mode (adds Message-Authenticator)")
	cmd.Flags().StringArray("attr", nil, "additional attribute as type:value (repeatable)")
	return cmd
}
