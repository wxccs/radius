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

// Package log defines the logging interface used across the radius library.
//
// The library never imports a concrete logging implementation. All packages
// obtain a Logger via log.Default and call its methods. Applications that
// embed the library call log.SetDefault at startup to inject their own
// logger (slog, logrus, zap, etc.).
//
// The interface signature mirrors log/slog.Logger so that the slog adapter
// (see slog.go) has zero overhead and callers can use the familiar
// key-value pair convention:
//
//	log.Default.With("func", "transport.UDPTransport.ReadPacket").
//	    Info("socket closed", "src", src.String())
//
// The default logger is a NopLogger that discards everything. This keeps
// the library silent unless the application explicitly opts in.
package log

// Logger is the structured logging interface used by the radius library.
// Implementations must be safe for concurrent use.
//
// The args parameter of each method follows the slog convention: a
// sequence of key-value pairs, where keys are strings and values are
// arbitrary. Implementations may format values however they like; slog
// adapters forward args verbatim, while logrus/zap adapters typically
// unpack each pair into their native field representation.
type Logger interface {
	// Debug logs a message at debug level with optional key-value pairs.
	Debug(msg string, args ...any)
	// Info logs a message at info level.
	Info(msg string, args ...any)
	// Warn logs a message at warn level.
	Warn(msg string, args ...any)
	// Error logs a message at error level.
	Error(msg string, args ...any)
	// With returns a new Logger that always includes the given key-value
	// pairs in every subsequent log record. The returned Logger shares no
	// mutable state with the original; both may be used concurrently.
	With(args ...any) Logger
}

// Default is the Logger used by every package in the library. It is
// initialized to a NopLogger that discards all output. Applications
// should call SetDefault at startup to inject a real logger.
//
// Default is safe for concurrent reads. SetDefault must not be called
// concurrently with reads; applications should set it exactly once at
// program start before any goroutine starts using the library.
var Default Logger = NopLogger{}

// SetDefault replaces the package-level Default logger. Intended to be
// called once at program startup; concurrent reads of Default during a
// concurrent SetDefault are not synchronized.
func SetDefault(l Logger) {
	if l == nil {
		Default = NopLogger{}
		return
	}
	Default = l
}

// GetDefault returns the current Default logger. Prefer storing the
// logger in a local variable over calling this repeatedly.
func GetDefault() Logger { return Default }

// NopLogger discards all log records. It is the zero value of Default
// so that the library is silent unless an application opts in.
type NopLogger struct{}

// Debug implements Logger.
func (NopLogger) Debug(string, ...any) {}

// Info implements Logger.
func (NopLogger) Info(string, ...any) {}

// Warn implements Logger.
func (NopLogger) Warn(string, ...any) {}

// Error implements Logger.
func (NopLogger) Error(string, ...any) {}

// With implements Logger.
func (n NopLogger) With(...any) Logger { return n }
