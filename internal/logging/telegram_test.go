package logging

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The Telegram sink must POST formatted records to /bot<token>/sendMessage with
// the configured chat_id and the message text.
func TestTelegramSink_PostsMessage(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
		forms []map[string]string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		paths = append(paths, r.URL.Path)
		forms = append(forms, map[string]string{"chat_id": r.PostForm.Get("chat_id"), "text": r.PostForm.Get("text")})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	h, ts := newTelegramSink("TOKEN123", "-100777", "text", slog.LevelInfo, srv.URL)
	lg := slog.New(h)
	lg.Info("detector rule announced", "event", "abc")
	ts.Close() // flushes synchronously

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 {
		t.Fatalf("got %d POSTs, want 1", len(paths))
	}
	if paths[0] != "/botTOKEN123/sendMessage" {
		t.Errorf("path = %q", paths[0])
	}
	if forms[0]["chat_id"] != "-100777" {
		t.Errorf("chat_id = %q", forms[0]["chat_id"])
	}
	if !strings.Contains(forms[0]["text"], "detector rule announced") {
		t.Errorf("text missing message: %q", forms[0]["text"])
	}
}

// A full queue must drop rather than block the logging path.
func TestChanWriter_DropsWhenFull(t *testing.T) {
	ch := make(chan []byte, 2)
	var dropped atomic.Int64
	w := &chanWriter{ch: ch, dropped: &dropped}
	for i := 0; i < 10; i++ {
		if _, err := w.Write([]byte("line")); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
	}
	if got := dropped.Load(); got != 8 { // 2 buffered, 8 dropped
		t.Fatalf("dropped = %d, want 8", got)
	}
}

// Close must be safe to call repeatedly and must not panic if records arrive after.
func TestTelegramSink_CloseIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	h, ts := newTelegramSink("T", "C", "text", slog.LevelInfo, srv.URL)
	ts.Close()
	ts.Close() // second close is a no-op
	// Logging after close must not panic (the line is simply dropped).
	slog.New(h).Info("after close")
}

func TestSplitMessage(t *testing.T) {
	// Short text: single chunk.
	if got := splitMessage("a\nb\n", 100); len(got) != 1 {
		t.Fatalf("short text => %d chunks, want 1", len(got))
	}
	// Many lines exceeding the cap split into multiple chunks, each within the cap.
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("0123456789\n") // 11 runes each => 550 total
	}
	chunks := splitMessage(b.String(), 100)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if runeLen(c) > 100 {
			t.Errorf("chunk %d has %d runes, exceeds cap", i, runeLen(c))
		}
	}
}
