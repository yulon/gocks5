package gocks5

import (
	"net"
	"strconv"
	"strings"
)

// IP with port address
type IPWPAddr struct {
	IP   net.IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

func (a *IPWPAddr) Network() string { return "ipwp" }

func ipEmptyString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func (a *IPWPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return net.JoinHostPort(ip+"%"+a.Zone, strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(ip, strconv.Itoa(a.Port))
}

type DomainAddr string

func (a DomainAddr) Network() string {
	return "domain"
}

func (a DomainAddr) String() string {
	return string(a)
}

func AddrToTCP(addr net.Addr) (*net.TCPAddr, error) {
	switch addr.(type) {
	case *net.TCPAddr:
		return addr.(*net.TCPAddr), nil

	case *IPWPAddr:
		ipwpAddr := addr.(*IPWPAddr)
		return &net.TCPAddr{IP: ipwpAddr.IP, Port: ipwpAddr.Port, Zone: ipwpAddr.Zone}, nil

	case *net.UDPAddr:
		udpAddr := addr.(*net.UDPAddr)
		return &net.TCPAddr{IP: udpAddr.IP, Port: udpAddr.Port, Zone: udpAddr.Zone}, nil
	}
	return net.ResolveTCPAddr("tcp", addr.String())
}

func AddrToUDP(addr net.Addr) (*net.UDPAddr, error) {
	switch addr.(type) {
	case *net.UDPAddr:
		return addr.(*net.UDPAddr), nil

	case *IPWPAddr:
		ipwpAddr := addr.(*IPWPAddr)
		return &net.UDPAddr{IP: ipwpAddr.IP, Port: ipwpAddr.Port, Zone: ipwpAddr.Zone}, nil

	case *net.TCPAddr:
		tcpAddr := addr.(*net.TCPAddr)
		return &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}, nil
	}
	return net.ResolveUDPAddr("udp", addr.String())
}

func IPWPToBytes(ip net.IP, port int) []byte {
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
	b[19] = byte(port >> 8)
	b[20] = byte(port)
	return b
}

func AddrToBytes(addr net.Addr) []byte {
	switch addr.(type) {
	case *net.TCPAddr:
		tcpAddr := addr.(*net.TCPAddr)
		return IPWPToBytes(tcpAddr.IP, tcpAddr.Port)

	case *net.UDPAddr:
		udpAddr := addr.(*net.UDPAddr)
		return IPWPToBytes(udpAddr.IP, udpAddr.Port)

	case *IPWPAddr:
		ipwpAddr := addr.(*IPWPAddr)
		return IPWPToBytes(ipwpAddr.IP, ipwpAddr.Port)
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
