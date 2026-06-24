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

	"github.com/wxccs/radius/protocol"
)

func newCoACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coa",
		Short: "Send a CoA-Request (RFC 5176)",
		Long:  "Send a RADIUS Change-of-Authorization-Request and print the CoA-ACK/NAK reply.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureTimeoutPositive(); err != nil {
				return err
			}
			attrs, err := attrsFromFlags(cmd)
			if err != nil {
				return err
			}

			c, closeFn, err := newClient()
			if err != nil {
				return err
			}
			defer closeFn()

			ctx, cancel := callCtx()
			defer cancel()

			resp, err := c.SendCoA(ctx, &protocol.CoARequest{Attributes: attrs})
			if err != nil {
				return fmt.Errorf("coa-request failed: %w", err)
			}
			fmt.Printf("Reply: %s (id=%d)\n", resp.Code, resp.Identifier)
			printAttrs(resp.Attributes)
			return nil
		},
	}
	cmd.Flags().StringArray("attr", nil, "attribute as type:value (repeatable). CoA-Request auto-includes Message-Authenticator.")
	return cmd
}
