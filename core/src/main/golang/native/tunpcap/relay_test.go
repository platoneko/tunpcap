package tunpcap

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeVPN returns the kernel side of a simulated TUN and the fd an Android
// VpnService would hand over (non-blocking, like Builder.setBlocking(false)).
func fakeVPN(t *testing.T) (*os.File, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fds[0]), "kernel"), fds[1]
}

type relayFixture struct {
	kernel *os.File // what the "app" sends / receives through the VPN
	stack  *os.File // what sing-tun sees
	relay  io.Closer
	writer *Writer
	path   string
}

func startFixture(t *testing.T) *relayFixture {
	t.Helper()
	kernel, vpnFd := fakeVPN(t)
	w, path := newTestWriter(t, 64)
	innerFd, closer, err := StartRelay(vpnFd, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(innerFd, true); err != nil {
		t.Fatal(err)
	}
	fx := &relayFixture{
		kernel: kernel,
		stack:  os.NewFile(uintptr(innerFd), "stack"),
		relay:  closer,
		writer: w,
		path:   path,
	}
	t.Cleanup(func() {
		_ = fx.kernel.Close()
		_ = fx.stack.Close()
		_ = fx.relay.Close()
		_, _, _ = fx.writer.Close()
	})
	return fx
}

func ipPacket(size int, fill byte) []byte {
	p := packet(size, fill)
	p[0] = 0x45 // IPv4, IHL=5
	return p
}

func send(t *testing.T, f *os.File, p []byte) {
	t.Helper()
	if _, err := f.Write(p); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, f *os.File) []byte {
	t.Helper()
	if err := f.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// stop tears the relay down the way tun.Start's closer does and returns the
// packets that reached the pcap.
func (fx *relayFixture) stop(t *testing.T) []pcapRecord {
	t.Helper()
	if err := fx.relay.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fx.writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, records := readPcap(t, fx.path)
	return records
}

func TestRelayForwardsAppToStack(t *testing.T) {
	fx := startFixture(t)
	p := ipPacket(60, 1)
	send(t, fx.kernel, p)
	if got := recv(t, fx.stack); !bytes.Equal(got, p) {
		t.Fatalf("stack received %d bytes, want the 60-byte packet", len(got))
	}
}

func TestRelayForwardsStackToApp(t *testing.T) {
	fx := startFixture(t)
	p := ipPacket(60, 2)
	send(t, fx.stack, p)
	if got := recv(t, fx.kernel); !bytes.Equal(got, p) {
		t.Fatalf("app received %d bytes, want the 60-byte packet", len(got))
	}
}

func TestRelayCapturesBothDirections(t *testing.T) {
	fx := startFixture(t)
	up, down := ipPacket(80, 3), ipPacket(120, 4)
	send(t, fx.kernel, up)
	recv(t, fx.stack)
	send(t, fx.stack, down)
	recv(t, fx.kernel)

	records := fx.stop(t)
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if !bytes.Equal(records[0].data, up) || !bytes.Equal(records[1].data, down) {
		t.Fatalf("captured packets do not match what crossed the relay")
	}
}

func TestRelayPreservesPacketBoundaries(t *testing.T) {
	fx := startFixture(t)
	sizes := []int{60, 1500, 9000}
	for i, n := range sizes {
		send(t, fx.kernel, ipPacket(n, byte(i)))
	}
	for i, n := range sizes {
		if got := recv(t, fx.stack); len(got) != n {
			t.Fatalf("packet %d: got %d bytes, want %d", i, len(got), n)
		}
	}
}

func TestRelayExitsWhenVPNClosed(t *testing.T) {
	fx := startFixture(t)
	for i := 0; i < 2; i++ {
		send(t, fx.kernel, ipPacket(100, byte(i)))
		recv(t, fx.stack)
	}

	// The VPN being revoked closes the kernel side under the relay.
	_ = fx.kernel.Close()
	done := make(chan struct{})
	go func() {
		_ = fx.relay.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not shut down after the VPN closed")
	}
	if records := fx.stop(t); len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
}
