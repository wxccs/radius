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
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	radiuslog "github.com/wxccs/radius/log"
)

// newRootCmd builds the root command with all subcommands attached.
// Global flags configure server address, shared secret, transport
// network, timeout, and log verbosity.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "radius-tool",
		Short:         "RADIUS client and server CLI",
		Long:          "radius-tool sends RADIUS requests (access/account/coa/disconnect) and can run a minimal echo server for testing.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return initLogger(viper.GetBool("verbose"))
		},
	}

	root.PersistentFlags().String("server", "127.0.0.1:1812", "RADIUS server address (host:port)")
	root.PersistentFlags().String("secret", "", "shared secret (required for client modes)")
	root.PersistentFlags().String("network", "udp", "transport network: udp or tcp")
	root.PersistentFlags().Duration("timeout", 5*time.Second, "per-call timeout")
	root.PersistentFlags().Bool("verbose", false, "enable debug-level logging")
	root.PersistentFlags().String("config", "", "path to config file (YAML/JSON/TOML)")

	if err := viper.BindPFlags(root.PersistentFlags()); err != nil {
		panic(fmt.Sprintf("bind flags: %v", err))
	}
	viper.SetEnvPrefix("RADIUS")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	root.AddCommand(newAccessCmd())
	root.AddCommand(newAccountCmd())
	root.AddCommand(newCoACmd())
	root.AddCommand(newDisconnectCmd())
	root.AddCommand(newServerCmd())
	return root
}

// initLogger configures logrus and bridges it into the library's
// log.Default so library internals emit through the same logger.
// verbose=true sets Debug level; otherwise Info.
func initLogger(verbose bool) error {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	})
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	// Bridge logrus into the library's Logger interface. The library
	// expects slog-style key-value pairs; we adapt by reading args two
	// at a time and forwarding them as logrus Fields.
	radiuslog.SetDefault(newLogrusAdapter(logrus.StandardLogger()))
	return nil
}

// logrusAdapter wraps a *logrus.Logger to satisfy radiuslog.Logger.
// It translates slog-style (msg, k, v, k, v, ...) calls into logrus
// WithFields(...).Log(...) calls.
type logrusAdapter struct {
	logger *logrus.Logger
	fields logrus.Fields
}

func newLogrusAdapter(l *logrus.Logger) *logrusAdapter {
	return &logrusAdapter{logger: l, fields: logrus.Fields{}}
}

func (a *logrusAdapter) Debug(msg string, args ...any) { a.log(logrus.DebugLevel, msg, args) }
func (a *logrusAdapter) Info(msg string, args ...any)  { a.log(logrus.InfoLevel, msg, args) }
func (a *logrusAdapter) Warn(msg string, args ...any)  { a.log(logrus.WarnLevel, msg, args) }
func (a *logrusAdapter) Error(msg string, args ...any) { a.log(logrus.ErrorLevel, msg, args) }

func (a *logrusAdapter) With(args ...any) radiuslog.Logger {
	return &logrusAdapter{
		logger: a.logger,
		fields: mergeFields(a.fields, args),
	}
}

func (a *logrusAdapter) log(level logrus.Level, msg string, args []any) {
	if !a.logger.IsLevelEnabled(level) {
		return
	}
	fields := mergeFields(a.fields, args)
	a.logger.WithFields(fields).Log(level, msg)
}

// mergeFields folds a base logrus.Fields with slog-style args (k, v, k, v, ...).
// Odd-length args drop the trailing key with a warning.
func mergeFields(base logrus.Fields, args []any) logrus.Fields {
	out := make(logrus.Fields, len(base)+len(args)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		out[key] = args[i+1]
	}
	return out
}

// Ensure logrusAdapter satisfies radiuslog.Logger at compile time.
var _ radiuslog.Logger = (*logrusAdapter)(nil)
