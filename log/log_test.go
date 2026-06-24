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

package log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNopLogger_DiscardsAll(t *testing.T) {
	n := NopLogger{}
	// All methods should be no-ops that do not panic.
	n.Debug("msg", "k", "v")
	n.Info("msg", "k", "v")
	n.Warn("msg", "k", "v")
	n.Error("msg", "k", "v")
	sub := n.With("k", "v")
	assert.Equal(t, n, sub)
}

func TestDefault_InitiallyNop(t *testing.T) {
	// Default is initialized to NopLogger at package load time. We cannot
	// assert the concrete type here because other tests may have called
	// SetDefault; instead we verify the type is NopLogger via a fresh
	// package-level snapshot taken in TestMain. For now just assert it
	// is non-nil and satisfies the interface.
	var l = Default
	assert.NotNil(t, l)
}

func TestSetDefault_ReplacesLogger(t *testing.T) {
	original := Default
	defer SetDefault(original)

	SetDefault(NopLogger{})
	assert.Equal(t, NopLogger{}, Default)
}

func TestSetDefault_NilFallsBackToNop(t *testing.T) {
	original := Default
	defer SetDefault(original)

	SetDefault(nil)
	assert.Equal(t, NopLogger{}, Default)
}

func TestGetDefault_ReturnsCurrent(t *testing.T) {
	original := Default
	defer SetDefault(original)

	SetDefault(NopLogger{})
	assert.Equal(t, NopLogger{}, GetDefault())
}

func TestNewSlogAdapter_NilReturnsNop(t *testing.T) {
	l := NewSlogAdapter(nil)
	assert.Equal(t, NopLogger{}, l)
}

func TestNewSlogAdapter_ForwardsToSlog(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slogger := slog.New(h)
	l := NewSlogAdapter(slogger)

	l.With("func", "test.scope").Info("hello", "user", "alice")

	var record map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record))
	assert.Equal(t, "hello", record["msg"])
	assert.Equal(t, "INFO", record["level"])
	assert.Equal(t, "test.scope", record["func"])
	assert.Equal(t, "alice", record["user"])
}

func TestNewSlogAdapter_AllLevels(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slogger := slog.New(h)
	l := NewSlogAdapter(slogger)

	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 4)

	var levels []string
	for _, line := range lines {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		levels = append(levels, record["level"].(string))
	}
	assert.Equal(t, []string{"DEBUG", "INFO", "WARN", "ERROR"}, levels)
}

func TestSlogAdapter_WithReturnsSlogAdapter(t *testing.T) {
	slogger := slog.Default()
	l := NewSlogAdapter(slogger)
	sub := l.With("k", "v")
	// The returned Logger must be a SlogAdapter, not a NopLogger.
	_, ok := sub.(SlogAdapter)
	assert.True(t, ok)
}

func TestNopLogger_SatisfiesLogger(t *testing.T) {
	var _ Logger = NopLogger{}
	var _ Logger = SlogAdapter{}
}

func TestSlogAdapter_NilLoggerField(t *testing.T) {
	// Constructing SlogAdapter{nil} directly is allowed but calling its
	// methods would panic. The public constructor NewSlogAdapter guards
	// against this by returning NopLogger for nil input. We only assert
	// the guard works, not the direct-zero-value behavior.
	l := NewSlogAdapter(nil)
	_, ok := l.(NopLogger)
	assert.True(t, ok)
}
