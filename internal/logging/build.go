package logging

import (
	"io"
	"log/slog"
	"os"
)

// SinkSpec is one resolved sink (level + scope filter + format). All==true means
// "every scope"; otherwise Scopes lists the accepted scopes (empty => disabled).
type SinkSpec struct {
	Level  slog.Level
	All    bool
	Scopes []string
	Format string // "text" or "json"
}

// TelegramSpec is a SinkSpec plus the Bot API credentials.
type TelegramSpec struct {
	SinkSpec
	BotToken string
	ChatID   string
}

// Options is the resolved logging configuration. Stderr is always built; Telegram
// is optional.
type Options struct {
	Stderr   SinkSpec
	Telegram *TelegramSpec
}

// New builds the multi-sink logger. The returned io.Closer flushes the Telegram
// sink (if any) on shutdown; it is safe to call even with no Telegram sink.
func New(o Options) (*slog.Logger, io.Closer) {
	sinks := []sink{{
		level:  o.Stderr.Level,
		all:    o.Stderr.All,
		scopes: toSet(o.Stderr.Scopes),
		h:      formatHandler(os.Stderr, o.Stderr.Format, o.Stderr.Level),
	}}

	var closers multiCloser
	if o.Telegram != nil {
		h, ts := newTelegramSink(o.Telegram.BotToken, o.Telegram.ChatID,
			o.Telegram.Format, o.Telegram.Level, defaultTelegramBase)
		sinks = append(sinks, sink{
			level:  o.Telegram.Level,
			all:    o.Telegram.All,
			scopes: toSet(o.Telegram.Scopes),
			h:      h,
		})
		closers = append(closers, ts)
	}

	return slog.New(newFanout(sinks)), closers
}

func toSet(scopes []string) map[string]bool {
	if len(scopes) == 0 {
		return nil
	}
	m := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		m[s] = true
	}
	return m
}

func formatHandler(w io.Writer, format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// multiCloser closes several io.Closers, returning the first error.
type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var err error
	for _, c := range m {
		if e := c.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}
