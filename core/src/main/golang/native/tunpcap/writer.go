// Package tunpcap tees raw IP packets crossing the VPN TUN into a pcap file.
package tunpcap

import (
	"bufio"
	"encoding/binary"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pcapMagic    = 0xa1b2c3d4
	pcapSnaplen  = 65535
	linktypeRaw  = 101 // packets start at the IP header, same as PCAPdroid dumps
	diskBufBytes = 1 << 20
)

type record struct {
	ts   time.Time
	data []byte
}

// Writer persists packets asynchronously so that Capture never stalls packet
// forwarding: when the disk side falls behind, packets are dropped from the
// pcap (and counted) instead of being delayed on the wire.
type Writer struct {
	f     *os.File
	queue chan record
	done  chan struct{}

	mu     sync.Mutex // guards closed and sends on queue
	closed bool

	written   uint64 // owned by the loop goroutine until done is closed
	dropped   atomic.Uint64
	err       error
	closeOnce sync.Once
}

func NewWriter(f *os.File, queueLen int) (*Writer, error) {
	var header [24]byte
	le := binary.LittleEndian
	le.PutUint32(header[0:], pcapMagic)
	le.PutUint16(header[4:], 2)
	le.PutUint16(header[6:], 4)
	le.PutUint32(header[16:], pcapSnaplen)
	le.PutUint32(header[20:], linktypeRaw)
	if _, err := f.Write(header[:]); err != nil {
		return nil, err
	}

	w := &Writer{
		f:     f,
		queue: make(chan record, queueLen),
		done:  make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

func (w *Writer) Capture(pkt []byte) {
	r := record{ts: time.Now(), data: append([]byte(nil), pkt...)}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	select {
	case w.queue <- r:
	default:
		w.dropped.Add(1)
	}
}

func (w *Writer) Close() (written, dropped uint64, err error) {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.queue)
		w.mu.Unlock()
	})
	<-w.done
	return w.written, w.dropped.Load(), w.err
}

func (w *Writer) loop() {
	defer close(w.done)

	bw := bufio.NewWriterSize(w.f, diskBufBytes)
	var hdr [16]byte
	le := binary.LittleEndian
	// Keep draining after a write error so Capture callers never block on a
	// full queue; the first error is reported by Close.
	for r := range w.queue {
		if w.err != nil {
			continue
		}
		le.PutUint32(hdr[0:], uint32(r.ts.Unix()))
		le.PutUint32(hdr[4:], uint32(r.ts.Nanosecond()/1000))
		le.PutUint32(hdr[8:], uint32(len(r.data)))
		le.PutUint32(hdr[12:], uint32(len(r.data)))
		if _, err := bw.Write(hdr[:]); err != nil {
			w.err = err
			continue
		}
		if _, err := bw.Write(r.data); err != nil {
			w.err = err
			continue
		}
		w.written++
	}

	if err := bw.Flush(); err != nil && w.err == nil {
		w.err = err
	}
	if err := w.f.Close(); err != nil && w.err == nil {
		w.err = err
	}
}
