package logging

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Telegram sink tuning. These are intentionally not configurable — the sink
// exposes only bot_token, chat_id, level, scope, format.
const (
	telegramQueueSize   = 1024            // bounded; overflow drops, never blocks logging
	telegramFlushEvery  = 2 * time.Second // batch window (also rate-limits the Bot API)
	telegramBatchBytes  = 3500            // flush once a batch reaches this size
	telegramMaxRunes    = 4000            // per-message cap (Telegram's hard limit is 4096)
	telegramCloseWait   = 5 * time.Second // bound on flushing remaining lines at shutdown
	telegramHTTPTimeout = 10 * time.Second
)

const defaultTelegramBase = "https://api.telegram.org"

// chanWriter is the io.Writer backing a Telegram sink's formatting handler. Each
// Write is one formatted record; it is enqueued without ever blocking the caller
// (the logging hot path). When the queue is full the line is dropped and counted.
type chanWriter struct {
	ch      chan []byte
	dropped *atomic.Int64
}

func (w *chanWriter) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case w.ch <- b:
	default:
		w.dropped.Add(1)
	}
	return len(p), nil
}

// telegramSink batches formatted log lines and POSTs them to the Telegram Bot
// API from a single background goroutine.
type telegramSink struct {
	chatID  string
	apiURL  string // <base>/bot<token>/sendMessage
	client  *http.Client
	ch      chan []byte
	dropped atomic.Int64
	quit    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// newTelegramSink builds a Telegram sink and starts its worker. It returns the
// formatting handler to register in the fanout and the sink itself as an io.Closer
// (Close flushes the remaining buffer). base is the API root (overridden in tests).
func newTelegramSink(token, chatID, format string, level slog.Level, base string) (slog.Handler, *telegramSink) {
	ts := &telegramSink{
		chatID: chatID,
		apiURL: base + "/bot" + token + "/sendMessage",
		client: &http.Client{Timeout: telegramHTTPTimeout},
		ch:     make(chan []byte, telegramQueueSize),
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	w := &chanWriter{ch: ts.ch, dropped: &ts.dropped}
	h := formatHandler(w, format, level)
	go ts.run()
	return h, ts
}

func (ts *telegramSink) run() {
	ticker := time.NewTicker(telegramFlushEvery)
	defer ticker.Stop()
	var buf bytes.Buffer
	for {
		select {
		case b := <-ts.ch:
			ts.accumulate(&buf, b)
		case <-ticker.C:
			ts.flush(&buf)
		case <-ts.quit:
			// Drain anything already queued, flush, and exit.
			for {
				select {
				case b := <-ts.ch:
					ts.accumulate(&buf, b)
				default:
					ts.flush(&buf)
					close(ts.done)
					return
				}
			}
		}
	}
}

func (ts *telegramSink) accumulate(buf *bytes.Buffer, b []byte) {
	if buf.Len() > 0 && buf.Len()+len(b) > telegramBatchBytes {
		ts.flush(buf)
	}
	buf.Write(b)
	if buf.Len() >= telegramBatchBytes {
		ts.flush(buf)
	}
}

// flush sends the buffered lines (prefixed with a drop note if any were lost) and
// resets the buffer. Sends nothing when there is nothing to report.
func (ts *telegramSink) flush(buf *bytes.Buffer) {
	var sb strings.Builder
	if n := ts.dropped.Swap(0); n > 0 {
		fmt.Fprintf(&sb, "[%d log lines dropped]\n", n)
	}
	sb.Write(buf.Bytes())
	buf.Reset()
	if sb.Len() == 0 {
		return
	}
	for _, chunk := range splitMessage(sb.String(), telegramMaxRunes) {
		ts.post(chunk)
	}
}

func (ts *telegramSink) post(text string) {
	form := url.Values{"chat_id": {ts.chatID}, "text": {text}}
	resp, err := ts.client.PostForm(ts.apiURL, form)
	if err != nil {
		fmt.Fprintf(os.Stderr, "telegram log: post failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		fmt.Fprintf(os.Stderr, "telegram log: status %d: %s\n", resp.StatusCode, bytes.TrimSpace(body))
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
}

// Close stops the worker, flushing any buffered lines (bounded by telegramCloseWait).
func (ts *telegramSink) Close() error {
	ts.once.Do(func() { close(ts.quit) })
	select {
	case <-ts.done:
	case <-time.After(telegramCloseWait):
	}
	return nil
}

// splitMessage breaks text into chunks of at most maxRunes runes, preferring to
// break on line boundaries; a single over-long line is hard-split by runes.
func splitMessage(text string, maxRunes int) []string {
	if runeLen(text) <= maxRunes {
		return []string{text}
	}
	var out []string
	var cur strings.Builder
	curRunes := 0
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
			curRunes = 0
		}
	}
	for _, line := range strings.SplitAfter(text, "\n") {
		if line == "" {
			continue
		}
		lr := runeLen(line)
		if lr > maxRunes { // single line too long: hard-split by runes
			flush()
			for _, piece := range chunkRunes(line, maxRunes) {
				out = append(out, piece)
			}
			continue
		}
		if curRunes+lr > maxRunes {
			flush()
		}
		cur.WriteString(line)
		curRunes += lr
	}
	flush()
	return out
}

func runeLen(s string) int { return len([]rune(s)) }

func chunkRunes(s string, max int) []string {
	r := []rune(s)
	var out []string
	for len(r) > 0 {
		n := max
		if n > len(r) {
			n = len(r)
		}
		out = append(out, string(r[:n]))
		r = r[n:]
	}
	return out
}
