package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ExecEvent is one observed process execution.
type ExecEvent struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
	PID  int       `json:"pid"`
	PPID int       `json:"ppid"`
	UID  int       `json:"uid"`
	// TTYNr is the controlling terminal (0 = none). Only tty-attached
	// processes count as student activity: the daemon's own task scripts
	// run in a fresh session with no controlling tty, which prevents a
	// check's own argv (which contains the searched pattern) from matching.
	TTYNr    int      `json:"ttyNr"`
	Argv     []string `json:"argv"`
	Cwd      string   `json:"cwd"`
	// ExitCode is the process exit code, populated after the process exits.
	// -1 means the exit event has not been received yet or the process exited
	// before the exit event could be correlated.
	ExitCode int `json:"exitCode"`
	// Env is captured eagerly for tty-attached processes (student
	// commands are low-rate; fast ones die before a lazy read could
	// happen). Empty for tty-less processes.
	Env []string `json:"-"`
}

// pendingExit tracks an exit event received before the exec event was
// published (race: EXIT fires before the harvest goroutine finishes).
type pendingExit struct {
	code      int
	expiresAt time.Time
}

// ExecWatcher records exec events into a bounded ring buffer, sourced from
// the kernel proc connector (netlink). If the connector is unavailable
// (missing CONFIG_PROC_EVENTS or CAP_NET_ADMIN), exec watching is simply
// disabled - exec-based checks (wait_exec, wait_env) then never fire.
type ExecWatcher struct {
	mu     sync.Mutex
	cond   *sync.Cond
	ring   []ExecEvent
	seq    uint64
	closed bool

	// exitCodes holds exit codes for PIDs whose EXIT event arrived before
	// (or just after) their exec event was published.  Entries expire after
	// exitTTL to cap memory usage.
	exitCodes map[int]pendingExit

	// subscribers receive a copy of every published ExecEvent (logger etc.).
	subscribers []chan ExecEvent

	// Source is "netlink" when the connector is active, "" when exec
	// watching is unavailable.
	Source string
}

const ringSize = 4096

// exitTTL is how long an unmatched exit-code entry is kept before eviction.
const exitTTL = 10 * time.Second

func NewExecWatcher() *ExecWatcher {
	w := &ExecWatcher{exitCodes: map[int]pendingExit{}}
	w.cond = sync.NewCond(&w.mu)
	return w
}

// Start begins watching via the kernel proc connector. It returns an error
// if the connector cannot be opened (missing CONFIG_PROC_EVENTS or, most
// commonly, no CAP_NET_ADMIN because the daemon is not root) - exec
// watching is the only mechanism, so the daemon treats this as fatal rather
// than running with silently-broken wait_exec/wait_env checks.
func (w *ExecWatcher) Start() error {
	sock, err := openProcConnector()
	if err != nil {
		return fmt.Errorf("proc connector unavailable (run shellgym as root): %w", err)
	}
	w.Source = "netlink"
	go w.netlinkLoop(sock)
	return nil
}

func (w *ExecWatcher) Close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

// Seq returns the current sequence number; events published after a given
// point have Seq greater than this.
func (w *ExecWatcher) Seq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// WaitMatch blocks until an event with Seq > after matches fn, returning it.
// Returns false when the deadline passes, ctx is canceled (e.g. the waiting
// check script was killed and its API connection dropped - without this,
// every killed attempt would leak a waiter that keeps scanning the ring on
// each broadcast), or the watcher closes.
func (w *ExecWatcher) WaitMatch(ctx context.Context, after uint64, deadline time.Time, fn func(ExecEvent) bool) (ExecEvent, bool) {
	timer := time.AfterFunc(time.Until(deadline), func() {
		w.mu.Lock()
		w.cond.Broadcast()
		w.mu.Unlock()
	})
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() {
		w.mu.Lock()
		w.cond.Broadcast()
		w.mu.Unlock()
	})
	defer stop()

	w.mu.Lock()
	defer w.mu.Unlock()
	scanned := after
	for {
		// The ring ascends by Seq - skip the already-scanned prefix instead
		// of re-running fn over all 4096 entries on every wake-up.
		i := sort.Search(len(w.ring), func(i int) bool { return w.ring[i].Seq > scanned })
		for _, ev := range w.ring[i:] {
			if fn(ev) {
				return ev, true
			}
		}
		scanned = w.seq
		if w.closed || ctx.Err() != nil || time.Now().After(deadline) {
			return ExecEvent{}, false
		}
		w.cond.Wait()
	}
}

// Snapshot returns events with Seq > after (for debugging APIs).
func (w *ExecWatcher) Snapshot(after uint64, limit int) []ExecEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []ExecEvent
	for _, ev := range w.ring {
		if ev.Seq > after {
			out = append(out, ev)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (w *ExecWatcher) publish(ev ExecEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seq++
	ev.Seq = w.seq
	ev.Time = time.Now()
	// Attach exit code if the EXIT event already arrived for this PID.
	ev.ExitCode = -1
	if pe, ok := w.exitCodes[ev.PID]; ok {
		ev.ExitCode = pe.code
		delete(w.exitCodes, ev.PID)
	}
	w.ring = append(w.ring, ev)
	if len(w.ring) > ringSize {
		w.ring = w.ring[len(w.ring)-ringSize:]
	}
	w.cond.Broadcast()
	// Fan out to subscribers (non-blocking: drop if the channel is full).
	for _, ch := range w.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
}

// recordExit stores the exit code for a PID. If an exec event for that PID
// is already in the ring (EXIT fired after publish), update it in-place.
func (w *ExecWatcher) recordExit(pid, code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Try to update an already-published event in the ring.
	for i := len(w.ring) - 1; i >= 0; i-- {
		if w.ring[i].PID == pid {
			w.ring[i].ExitCode = code
			// Notify subscribers of the updated event so the logger can
			// write the final record.
			for _, ch := range w.subscribers {
				select {
				case ch <- w.ring[i]:
				default:
				}
			}
			w.cond.Broadcast()
			return
		}
	}
	// EXIT arrived before the harvest goroutine finished; stash for publish.
	w.evictExpiredLocked()
	w.exitCodes[pid] = pendingExit{code: code, expiresAt: time.Now().Add(exitTTL)}
}

// evictExpiredLocked removes stale entries from exitCodes. Must be called
// with w.mu held.
func (w *ExecWatcher) evictExpiredLocked() {
	now := time.Now()
	for pid, pe := range w.exitCodes {
		if now.After(pe.expiresAt) {
			delete(w.exitCodes, pid)
		}
	}
}

// Subscribe returns a channel that receives a copy of every published
// ExecEvent. The caller must drain the channel promptly; events are dropped
// (not queued beyond bufSize) to avoid blocking the watcher.
func (w *ExecWatcher) Subscribe(bufSize int) <-chan ExecEvent {
	ch := make(chan ExecEvent, bufSize)
	w.mu.Lock()
	w.subscribers = append(w.subscribers, ch)
	w.mu.Unlock()
	return ch
}

// --- netlink proc connector -------------------------------------------------

const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002
	procEventExit     = 0x00000004
	nlMsgDone         = 0x3
)

func openProcConnector() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		return -1, err
	}
	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}
	if err := unix.Bind(sock, addr); err != nil {
		unix.Close(sock)
		return -1, err
	}
	// Fork bursts (builds, package installs, parallel scripts) can outpace
	// the reader; a roomy receive buffer makes overflow (ENOBUFS) rare.
	// FORCE ignores rmem_max but needs CAP_NET_ADMIN - same capability the
	// connector itself needs, so the fallback is mostly for tests.
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20); err != nil {
		_ = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	}
	if err := sendProcListen(sock, procCnMcastListen); err != nil {
		unix.Close(sock)
		return -1, err
	}
	return sock, nil
}

func sendProcListen(sock int, op uint32) error {
	// nlmsghdr + cn_msg + op
	buf := make([]byte, 16+20+4)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], uint32(len(buf))) // nlmsg_len
	le.PutUint16(buf[4:], nlMsgDone)        // nlmsg_type
	le.PutUint32(buf[12:], uint32(os.Getpid()))
	// cn_msg: idx, val, seq, ack, len, flags
	le.PutUint32(buf[16:], cnIdxProc)
	le.PutUint32(buf[20:], cnValProc)
	le.PutUint16(buf[32:], 4) // data len
	le.PutUint32(buf[36:], op)
	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(sock, buf, 0, addr)
}

func (w *ExecWatcher) netlinkLoop(sock int) {
	defer unix.Close(sock)
	buf := make([]byte, 65536)
	le := binary.LittleEndian
	var lastOverflowLog time.Time
	for {
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return
		}
		n, _, err := unix.Recvfrom(sock, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.ENOBUFS {
				// The kernel dropped events because our receive buffer
				// overflowed (fork burst). The socket is still healthy;
				// events in the gap are lost, which wait_* checks absorb
				// by re-polling - so keep reading, never disable.
				if time.Since(lastOverflowLog) > time.Minute {
					lastOverflowLog = time.Now()
					log.Printf("execwatch: netlink overflow (ENOBUFS): some exec events were lost")
				}
				continue
			}
			log.Printf("execwatch: netlink read error: %v; exec-based checks disabled", err)
			w.Source = ""
			return
		}
		// walk netlink messages
		for off := 0; off+16 <= n; {
			msgLen := int(le.Uint32(buf[off:]))
			if msgLen < 16 || off+msgLen > n {
				break
			}
			// cn_msg payload at off+16, proc_event at off+16+20
			pe := off + 16 + 20
			if pe+16 <= n {
				what := le.Uint32(buf[pe:])
				switch what {
				case procEventExec:
					// exec event: process pid at pe+16 (after what, cpu, timestamp[8])
					pid := int(le.Uint32(buf[pe+16:]))
					// Harvest concurrently: a burst of execs (shell pipelines,
					// login scripts) harvested serially would delay the later
					// /proc reads past the lifetime of short-lived commands
					// like `ss`, silently dropping their events.
					go func(pid int) {
						if ev, ok := harvestProc(pid); ok {
							w.publish(ev)
						}
					}(pid)
				case procEventExit:
					// exit event layout: pid at pe+16, exit_code at pe+20
					if pe+24 <= n {
						pid := int(le.Uint32(buf[pe+16:]))
						exitCode := int(le.Uint32(buf[pe+20:]))
						w.recordExit(pid, exitCode)
					}
				}
			}
			off += nlmsgAlign(msgLen)
		}
	}
}

func nlmsgAlign(n int) int { return (n + 3) &^ 3 }

// harvestProc reads argv/uid/ppid of a freshly-exec'ed pid from /proc. The
// proc connector fires AFTER the new mm is installed, so /proc reflects the
// executed command. Very short-lived processes may be gone already - that
// is fine for reps where the interesting commands run at human speed.
func harvestProc(pid int) (ExecEvent, bool) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(raw) == 0 {
		return ExecEvent{}, false
	}
	argv := splitNul(string(raw))
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ExecEvent{}, false
	}
	// -1 = unknown: the process may exit before we can read its stat (very
	// short-lived commands like `ls`). Consumers must only reject a
	// CONFIRMED 0 - daemon-spawned scripts live long enough for the read
	// to succeed, so unknown means "probably a fast interactive command".
	ttyNr := -1
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		if f := statFields(string(stat)); len(f) > 6 {
			if v, err := strconv.Atoi(f[6]); err == nil {
				ttyNr = v
			}
		}
	}
	uid, ppid := -1, -1
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				uid, _ = strconv.Atoi(f[0])
			}
		} else if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			ppid, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	ev := ExecEvent{PID: pid, PPID: ppid, UID: uid, TTYNr: ttyNr, Argv: argv, ExitCode: -1}
	// Capture working directory; may fail for very short-lived processes.
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		ev.Cwd = cwd
	}
	if ttyNr != 0 {
		// Eager env capture (bounded): fast interactive commands are gone
		// before wait_env could read /proc lazily.
		if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil && len(raw) > 0 {
			if len(raw) > 32*1024 {
				raw = raw[:32*1024]
			}
			ev.Env = splitNul(string(raw))
		}
	}
	return ev, true
}

// splitNul splits a NUL-separated /proc string (cmdline, environ).
func splitNul(s string) []string {
	return strings.Split(strings.TrimRight(s, "\x00"), "\x00")
}
