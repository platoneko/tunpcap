package tun

import (
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"cfa/native/tunpcap"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// Start runs the netstack on the VPN fd. pcapFd < 0 keeps upstream behavior;
// otherwise a relay between the VPN fd and the netstack tees every packet
// into a pcap written to pcapFd (see package tunpcap).
func Start(fd int, stack, gateway, portal, dns string, pcapFd int) (io.Closer, error) {
	if pcapFd < 0 {
		return startStack(fd, stack, gateway, portal, dns)
	}

	pcapFile := os.NewFile(uintptr(pcapFd), "pcap")
	writer, err := tunpcap.NewWriter(pcapFile, pcapQueueLen)
	if err != nil {
		_ = pcapFile.Close()
		log.Errorln("TunPcap: open pcap: %s", err)
		return nil, err
	}
	innerFd, relay, err := tunpcap.StartRelay(fd, writer)
	if err != nil {
		_, _, _ = writer.Close()
		log.Errorln("TunPcap: start relay: %s", err)
		return nil, err
	}
	listener, err := startStack(innerFd, stack, gateway, portal, dns)
	if err != nil {
		_ = relay.Close()
		_, _, _ = writer.Close()
		return nil, err
	}
	log.Infoln("TunPcap: capturing to fd %d", pcapFd)
	return &captureCloser{listener: listener, relay: relay, writer: writer}, nil
}

const pcapQueueLen = 4096

type captureCloser struct {
	listener io.Closer
	relay    io.Closer
	writer   *tunpcap.Writer
}

// Close stops the netstack first, then the relay, and only then finalizes the
// pcap so that every forwarded packet is on disk before the VPN goes away.
func (c *captureCloser) Close() error {
	err := c.listener.Close()
	_ = c.relay.Close()
	written, dropped, werr := c.writer.Close()
	if werr != nil {
		log.Errorln("TunPcap: finalize pcap: %s", werr)
	}
	log.Infoln("TunPcap: stopped written=%d dropped=%d", written, dropped)
	if err != nil {
		return err
	}
	return werr
}

func startStack(fd int, stack, gateway, portal, dns string) (io.Closer, error) {
	log.Debugln("TUN: fd = %d, stack = %s, gateway = %s, portal = %s, dns = %s", fd, stack, gateway, portal, dns)

	tunStack, ok := C.StackTypeMapping[strings.ToLower(stack)]
	if !ok {
		tunStack = C.TunSystem
	}

	var prefix4 []netip.Prefix
	var prefix6 []netip.Prefix
	for _, gatewayStr := range strings.Split(gateway, ",") { // "172.19.0.1/30" or "172.19.0.1/30,fdfe:dcba:9876::1/126"
		gatewayStr = strings.TrimSpace(gatewayStr)
		if len(gatewayStr) == 0 {
			continue
		}
		prefix, err := netip.ParsePrefix(gatewayStr)
		if err != nil {
			log.Errorln("TUN:", err)
			return nil, err
		}

		if prefix.Addr().Is4() {
			prefix4 = append(prefix4, prefix)
		} else {
			prefix6 = append(prefix6, prefix)
		}
	}

	var dnsHijack []string
	for _, dnsStr := range strings.Split(dns, ",") { // "172.19.0.2" or "0.0.0.0"
		dnsStr = strings.TrimSpace(dnsStr)
		if len(dnsStr) == 0 {
			continue
		}
		dnsHijack = append(dnsHijack, net.JoinHostPort(dnsStr, "53"))
	}

	options := LC.Tun{
		Enable:              true,
		Device:              sing_tun.InterfaceName,
		Stack:               tunStack,
		DNSHijack:           dnsHijack,
		AutoRoute:           false, // had set route in TunService.kt
		AutoDetectInterface: false, // implements by VpnService::protect
		Inet4Address:        prefix4,
		Inet6Address:        prefix6,
		MTU:                 9000, // private const val TUN_MTU = 9000 in TunService.kt
		FileDescriptor:      fd,
	}

	tunOptions, _ := json.Marshal(options)
	log.Debugln(string(tunOptions))

	listener, err := sing_tun.New(options, tunnel.Tunnel)
	if err != nil {
		log.Errorln("TUN:", err)
		return nil, err
	}

	return listener, nil
}
