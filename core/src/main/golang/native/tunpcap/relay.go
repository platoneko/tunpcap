package tunpcap

import (
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const relayBufBytes = 65535

// StartRelay inserts a packet relay between the VPN TUN fd and the netstack:
//
//	app <-> vpnFd <-> relay (tee to w) <-> innerFd <-> sing-tun
//
// The returned innerFd behaves like a TUN fd (SOCK_SEQPACKET keeps packet
// boundaries) and is owned by the caller. The relay owns vpnFd; its closer
// closes vpnFd and the relay's socket end, but leaves w open for the caller.
func StartRelay(vpnFd int, w *Writer) (innerFd int, closer io.Closer, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	// Non-blocking fds go through Go's poller, so Close unblocks pending reads.
	for _, fd := range []int{vpnFd, fds[0]} {
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fds[0])
			_ = unix.Close(fds[1])
			return -1, nil, err
		}
	}

	r := &relay{
		vpn:  os.NewFile(uintptr(vpnFd), "vpn"),
		peer: os.NewFile(uintptr(fds[0]), "relay"),
	}
	r.wg.Add(2)
	go r.pump(r.vpn, r.peer, w)
	go r.pump(r.peer, r.vpn, w)
	return fds[1], r, nil
}

type relay struct {
	vpn, peer *os.File
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// pump copies packets one by one; any read or write error (including the
// other side closing) ends this direction.
func (r *relay) pump(src, dst *os.File, w *Writer) {
	defer r.wg.Done()

	buf := make([]byte, relayBufBytes)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w.Capture(buf[:n])
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *relay) Close() error {
	r.closeOnce.Do(func() {
		_ = r.vpn.Close()
		_ = r.peer.Close()
	})
	r.wg.Wait()
	return nil
}
