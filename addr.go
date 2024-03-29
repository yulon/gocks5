package gocks5

import (
	"net"
	"strconv"
	"strings"

	"github.com/yulon/go-netil"
)

func IPPortToBytes(ip net.IP, port int) []byte {
	if len(ip) == 0 {
		ip = net.IPv4zero
	}
	ipv4 := ip.To4()
	if ipv4 != nil {
		b := make([]byte, 7)
		b[0] = AtypIPv4
		copy(b[1:], ipv4)
		b[5] = byte(port >> 8)
		b[6] = byte(port)
		return b
	}
	b := make([]byte, 19)
	b[0] = AtypIPv6
	copy(b[1:], ip)
	b[17] = byte(port >> 8)
	b[18] = byte(port)
	return b
}

func AddrToBytes(addr net.Addr) []byte {
	if addr == nil {
		return IPPortToBytes(nil, 0)
	}

	switch addr.(type) {
	case *net.TCPAddr:
		tcpAddr := addr.(*net.TCPAddr)
		return IPPortToBytes(tcpAddr.IP, tcpAddr.Port)

	case *net.UDPAddr:
		udpAddr := addr.(*net.UDPAddr)
		return IPPortToBytes(udpAddr.IP, udpAddr.Port)

	case *netil.IPPortAddr:
		ipAddr := addr.(*netil.IPPortAddr)
		return IPPortToBytes(ipAddr.IP, ipAddr.Port)
	}

	dap := strings.Split(addr.String(), ":")
	if len(dap) != 2 {
		return nil
	}

	domain := dap[0]
	domainLen := len(domain)
	if len(dap) != 2 || domainLen > 255 {
		return nil
	}

	b := make([]byte, 4+domainLen)
	b[0] = AtypDomain
	b[1] = byte(domainLen)
	copy(b[2:], []byte(domain))

	port, err := strconv.Atoi(dap[1])
	if err != nil {
		return nil
	}
	base := 2 + domainLen
	b[base] = byte(port >> 8)
	base++
	b[base] = byte(port)
	return b
}

func IPPortToBytesBack(b []byte, ip net.IP, port int) int {
	if len(ip) == 0 {
		ip = net.IPv4zero
	}
	lst := len(b) - 1
	ipv4 := ip.To4()
	if ipv4 != nil {
		b[lst-6] = AtypIPv4
		copy(b[lst-5:lst-1], ipv4)
		b[lst-1] = byte(port >> 8)
		b[lst] = byte(port)
		return 7
	}
	b[lst-18] = AtypIPv6
	copy(b[lst-17:lst-1], ip)
	b[lst-1] = byte(port >> 8)
	b[lst] = byte(port)
	return 19
}

func AddrToBytesBack(b []byte, addr net.Addr) int {
	if addr == nil {
		return IPPortToBytesBack(b, nil, 0)
	}

	switch addr.(type) {
	case *net.TCPAddr:
		tcpAddr := addr.(*net.TCPAddr)
		return IPPortToBytesBack(b, tcpAddr.IP, tcpAddr.Port)

	case *net.UDPAddr:
		udpAddr := addr.(*net.UDPAddr)
		return IPPortToBytesBack(b, udpAddr.IP, udpAddr.Port)

	case *netil.IPPortAddr:
		ipAddr := addr.(*netil.IPPortAddr)
		return IPPortToBytesBack(b, ipAddr.IP, ipAddr.Port)
	}

	dap := strings.Split(addr.String(), ":")
	if len(dap) != 2 {
		return 0
	}

	domain := dap[0]
	domainLen := len(domain)
	if len(dap) != 2 || domainLen > 255 {
		return 0
	}

	lst := len(b) - 1

	b[lst-3-domainLen] = AtypDomain
	b[lst-2-domainLen] = byte(domainLen)
	copy(b[lst-1-domainLen:lst-1], []byte(domain))

	port, err := strconv.Atoi(dap[1])
	if err != nil {
		return 0
	}
	b[lst-1] = byte(port >> 8)
	b[lst] = byte(port)

	return 4 + domainLen
}
