// Package logx is a tiny leveled logger (debug/info/warn/error) with no
// dependencies, mirroring the Node agent's src/logger.js behaviour: a level
// gate and a single-line, timestamped format.
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

// ParseLevel maps a name (debug/info/warn/error) to a Level, defaulting to Info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return Debug
	case "warn", "warning":
		return Warn
	case "error":
		return Error
	default:
		return Info
	}
}

// Logger writes leveled lines to an io.Writer. The zero value is not usable;
// use New.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	now   func() time.Time
}

// New returns a Logger gated at the given level, writing to stderr.
func New(level Level) *Logger {
	return &Logger{out: os.Stderr, level: level, now: time.Now}
}

// WithWriter overrides the destination (used in tests).
func (l *Logger) WithWriter(w io.Writer) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
	return l
}

func (l *Logger) log(lv Level, tag, format string, args ...any) {
	if lv < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.now().UTC().Format(time.RFC3339)
	fmt.Fprintf(l.out, "%s %s %s\n", ts, tag, fmt.Sprintf(format, args...))
}

// Debugf logs at debug level.
func (l *Logger) Debugf(format string, args ...any) { l.log(Debug, "DEBUG", format, args...) }

// Infof logs at info level.
func (l *Logger) Infof(format string, args ...any) { l.log(Info, "INFO", format, args...) }

// Warnf logs at warn level.
func (l *Logger) Warnf(format string, args ...any) { l.log(Warn, "WARN", format, args...) }

// Errorf logs at error level.
func (l *Logger) Errorf(format string, args ...any) { l.log(Error, "ERROR", format, args...) }
