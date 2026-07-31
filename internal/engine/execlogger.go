package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
)

// ExecLogger writes TTY-attached ExecEvents to an append-only JSONL file.
// Each line is a complete JSON object representing one command execution.
// Exit-code updates (when recordExit fires after publish) are written as
// additional lines with the same Seq so consumers can correlate them.
//
// Usage:
//
//	logger, err := NewExecLogger("/var/log/shellgym-commands.jsonl")
//	ch := watcher.Subscribe(256)
//	go logger.Run(ch)
//	defer logger.Close()
type ExecLogger struct {
	mu   sync.Mutex
	f    *os.File
	bw   *bufio.Writer
	path string
}

// NewExecLogger opens (or creates) path for append-only writing.
func NewExecLogger(path string) (*ExecLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("exec logger: open %s: %w", path, err)
	}
	return &ExecLogger{f: f, bw: bufio.NewWriter(f), path: path}, nil
}

// Run reads events from ch and writes them to the log file. It returns when
// ch is closed. Run is intended to be called in its own goroutine.
func (l *ExecLogger) Run(ch <-chan ExecEvent) {
	for ev := range ch {
		// Only log student (TTY-attached) commands.
		if ev.TTYNr == 0 {
			continue
		}
		l.write(ev)
	}
}

func (l *ExecLogger) write(ev ExecEvent) {
	line, err := json.Marshal(ev)
	if err != nil {
		log.Printf("exec logger: marshal: %v", err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bw.Write(line)
	l.bw.WriteByte('\n')
	if err := l.bw.Flush(); err != nil {
		log.Printf("exec logger: write %s: %v", l.path, err)
	}
}

// Close flushes and closes the log file.
func (l *ExecLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.bw.Flush(); err != nil {
		_ = l.f.Close()
		return err
	}
	return l.f.Close()
}
