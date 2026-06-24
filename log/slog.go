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

package log

import "log/slog"

// SlogAdapter wraps a *slog.Logger to satisfy the Logger interface.
// Because the Logger interface mirrors slog.Logger's method signatures,
// each call is a direct forward with no allocation.
//
// A nil *slog.Logger is treated as a NopLogger to avoid nil-pointer
// dereferences in callers that obtain a logger from third-party code.
type SlogAdapter struct {
	l *slog.Logger
}

// NewSlogAdapter returns a Logger backed by l. If l is nil, the returned
// Logger discards all output.
func NewSlogAdapter(l *slog.Logger) Logger {
	if l == nil {
		return NopLogger{}
	}
	return SlogAdapter{l: l}
}

// Debug implements Logger.
func (s SlogAdapter) Debug(msg string, args ...any) { s.l.Debug(msg, args...) }

// Info implements Logger.
func (s SlogAdapter) Info(msg string, args ...any) { s.l.Info(msg, args...) }

// Warn implements Logger.
func (s SlogAdapter) Warn(msg string, args ...any) { s.l.Warn(msg, args...) }

// Error implements Logger.
func (s SlogAdapter) Error(msg string, args ...any) { s.l.Error(msg, args...) }

// With implements Logger. The returned Logger shares the underlying
// *slog.Logger after it has been augmented with args.
func (s SlogAdapter) With(args ...any) Logger {
	return SlogAdapter{l: s.l.With(args...)}
}
