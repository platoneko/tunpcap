package tunpcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type pcapHeader struct {
	magic    uint32
	major    uint16
	minor    uint16
	snaplen  uint32
	linktype uint32
}

type pcapRecord struct {
	tsSec, tsUsec uint32
	inclLen       uint32
	origLen       uint32
	data          []byte
}

func readPcap(t *testing.T, path string) (pcapHeader, []pcapRecord) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return parsePcap(t, raw)
}

func parsePcap(t *testing.T, raw []byte) (pcapHeader, []pcapRecord) {
	t.Helper()
	if len(raw) < 24 {
		t.Fatalf("pcap too short: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	h := pcapHeader{
		magic:    le.Uint32(raw[0:]),
		major:    le.Uint16(raw[4:]),
		minor:    le.Uint16(raw[6:]),
		snaplen:  le.Uint32(raw[16:]),
		linktype: le.Uint32(raw[20:]),
	}
	var records []pcapRecord
	for off := 24; off < len(raw); {
		if off+16 > len(raw) {
			t.Fatalf("truncated record header at %d", off)
		}
		r := pcapRecord{
			tsSec:   le.Uint32(raw[off:]),
			tsUsec:  le.Uint32(raw[off+4:]),
			inclLen: le.Uint32(raw[off+8:]),
			origLen: le.Uint32(raw[off+12:]),
		}
		off += 16
		end := off + int(r.inclLen)
		if end > len(raw) {
			t.Fatalf("truncated record data at %d", off)
		}
		r.data = raw[off:end]
		records = append(records, r)
		off = end
	}
	return h, records
}

func newTestWriter(t *testing.T, queueLen int) (*Writer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWriter(f, queueLen)
	if err != nil {
		t.Fatal(err)
	}
	return w, path
}

func packet(size int, fill byte) []byte {
	return bytes.Repeat([]byte{fill}, size)
}

func TestHeaderIsRawLinktype(t *testing.T) {
	w, path := newTestWriter(t, 16)
	if _, _, err := w.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 24 {
		t.Fatalf("file size = %d, want 24", len(raw))
	}
	h, _ := parsePcap(t, raw)
	if h.magic != 0xa1b2c3d4 || h.major != 2 || h.minor != 4 {
		t.Fatalf("header = %+v", h)
	}
	if h.snaplen != 65535 {
		t.Fatalf("snaplen = %d, want 65535", h.snaplen)
	}
	if h.linktype != 101 {
		t.Fatalf("linktype = %d, want 101", h.linktype)
	}
}

func TestCloseFlushesQueuedPackets(t *testing.T) {
	w, path := newTestWriter(t, 16)
	pkts := [][]byte{packet(20, 1), packet(1500, 2), packet(9000, 3)}
	for _, p := range pkts {
		w.Capture(p)
	}

	written, dropped, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if written != 3 || dropped != 0 {
		t.Fatalf("written=%d dropped=%d, want 3/0", written, dropped)
	}

	_, records := readPcap(t, path)
	if len(records) != len(pkts) {
		t.Fatalf("records = %d, want %d", len(records), len(pkts))
	}
	var prev time.Time
	for i, r := range records {
		if int(r.inclLen) != len(pkts[i]) || r.origLen != r.inclLen {
			t.Fatalf("record %d: incl=%d orig=%d, want %d", i, r.inclLen, r.origLen, len(pkts[i]))
		}
		if !bytes.Equal(r.data, pkts[i]) {
			t.Fatalf("record %d payload mismatch", i)
		}
		ts := time.Unix(int64(r.tsSec), int64(r.tsUsec)*1000)
		if r.tsSec == 0 || ts.Before(prev) {
			t.Fatalf("record %d bad timestamp %v (prev %v)", i, ts, prev)
		}
		prev = ts
	}
}

func TestCaptureCopiesInput(t *testing.T) {
	w, path := newTestWriter(t, 16)
	p := packet(40, 7)
	w.Capture(p)
	for i := range p {
		p[i] = 0
	}
	if _, _, err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, records := readPcap(t, path)
	if len(records) != 1 || !bytes.Equal(records[0].data, packet(40, 7)) {
		t.Fatalf("captured data changed after Capture returned")
	}
}

func TestCaptureNeverBlocksWhenQueueFull(t *testing.T) {
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w, err := NewWriter(wr, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Nobody reads the pipe yet, so the disk side stalls once its buffers fill.
	const total = 1000
	done := make(chan struct{})
	go func() {
		for i := 0; i < total; i++ {
			w.Capture(packet(9000, byte(i)))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Capture blocked while the writer was stalled")
	}

	go func() { _, _ = io.Copy(io.Discard, r) }()
	written, dropped, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if dropped == 0 {
		t.Fatalf("dropped = 0, want > 0")
	}
	if written+dropped != total {
		t.Fatalf("written+dropped = %d, want %d", written+dropped, total)
	}
}

func TestCaptureAfterCloseIsNoop(t *testing.T) {
	w, _ := newTestWriter(t, 16)
	w.Capture(packet(20, 1))
	written, dropped, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}

	w.Capture(packet(20, 2))
	written2, dropped2, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if written2 != written || dropped2 != dropped {
		t.Fatalf("second Close = %d/%d, want %d/%d", written2, dropped2, written, dropped)
	}
}
