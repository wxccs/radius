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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/wxccs/radius/packet"
	"github.com/wxccs/radius/protocol"
	"github.com/wxccs/radius/types"
)

// acctStatusType maps a human status name to its RFC 2866 §5.1 numeric value.
var acctStatusType = map[string]uint32{
	"start":          1,
	"stop":           2,
	"interim-update": 3,
	"accounting-on":  7,
	"accounting-off": 8,
}

func newAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Send an Accounting-Request",
		Long:  "Send a RADIUS Accounting-Request and print the Accounting-Response reply.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureTimeoutPositive(); err != nil {
				return err
			}
			attrs, err := attrsFromFlags(cmd)
			if err != nil {
				return err
			}

			// Prepend Acct-Status-Type derived from --status.
			statusStr, _ := cmd.Flags().GetString("status")
			status, ok := acctStatusType[statusStr]
			if !ok {
				if n, perr := strconv.ParseUint(statusStr, 10, 32); perr == nil {
					status = uint32(n)
				} else {
					return fmt.Errorf("invalid --status %q (try start/stop/interim-update)", statusStr)
				}
			}
			attrs = append([]packet.Attribute{packet.NewInteger(types.AttrAcctStatusType, status)}, attrs...)

			c, closeFn, err := newClient()
			if err != nil {
				return err
			}
			defer closeFn()

			ctx, cancel := callCtx()
			defer cancel()

			resp, err := c.Account(ctx, &protocol.AccountingRequest{Attributes: attrs})
			if err != nil {
				return fmt.Errorf("accounting-request failed: %w", err)
			}
			fmt.Printf("Reply: Accounting-Response (id=%d)\n", resp.Identifier)
			printAttrs(resp.Attributes)
			return nil
		},
	}
	cmd.Flags().String("status", "start", "Acct-Status-Type: start, stop, interim-update, accounting-on, accounting-off, or a number")
	cmd.Flags().StringArray("attr", nil, "additional attribute as type:value (repeatable)")
	return cmd
}
