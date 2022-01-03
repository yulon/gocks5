package gocks5

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

type Conn struct {
	net.Conn
}

func (con *Conn) WriteAddr(typ byte, addr net.Addr) error {
	/*
		+----+-----+-------+------+----------+------+
		|VER | TYP |  RSV  | ATYP |   ADDR   | PORT |
		+----+-----+-------+------+----------+------+
		| 1  |  1  | X'00' |  1   | Variable |  2   |
		+----+-----+-------+------+----------+------+
	*/
	return writeAll(con, append([]byte{Ver, typ, 0}, AddrToBytes(addr)...))
}

var ErrorUnknowAddress = errors.New("unknow address")

func (con *Conn) ReadAddr() (byte, net.Addr, error) {
	var vtra [4]byte
	err := readFull(con, vtra[:])
	if err != nil {
		return 0, nil, err
	}
	switch vtra[3] {
	case AtypIPv4:
		var addrBytes [6]byte
		err := readFull(con, addrBytes[:])
		if err != nil {
			return vtra[1], nil, err
		}
		return vtra[1], &IPAddr{
			IP:   net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]),
			Port: (int(addrBytes[4]) << 8) | int(addrBytes[5]),
		}, nil

	case AtypIPv6:
		var addrBytes [18]byte
		err := readFull(con, addrBytes[:])
		if err != nil {
			return vtra[1], nil, err
		}
		return vtra[1], &IPAddr{
			IP:   addrBytes[:16],
			Port: (int(addrBytes[16]) << 8) | int(addrBytes[17]),
		}, nil

	case AtypDomain:
		var domainLenBuf [1]byte
		err := readFull(con, domainLenBuf[:])
		if err != nil {
			return vtra[1], nil, err
		}
		domainLen := int(domainLenBuf[0])
		addrBytes := make([]byte, domainLen+2)
		err = readFull(con, addrBytes)
		if err != nil {
			return vtra[1], nil, err
		}
		return vtra[1], DomainAddr(string(addrBytes[:domainLen]) + ":" + strconv.Itoa((int(addrBytes[domainLen])<<8)|int(addrBytes[domainLen+1]))), nil
	}
	return vtra[1], nil, ErrorUnknowAddress
}

func (con *Conn) ResolveRemoteAddr(addr net.Addr) (net.Addr, error) {
	var port int
	switch addr.(type) {
	case *IPAddr:
		port = addr.(*IPAddr).Port
	case *net.TCPAddr:
		port = addr.(*net.TCPAddr).Port
	case *net.UDPAddr:
		port = addr.(*net.UDPAddr).Port
	default:
		addrStr := addr.String()
		pos := strings.LastIndexByte(addr.String(), ':')
		var err error
		port, err = strconv.Atoi(addrStr[pos+1:])
		if err != nil {
			return nil, err
		}
	}
	negSvrTCPAddr, err := AddrToTCP(con.RemoteAddr())
	if err != nil {
		return nil, err
	}
	return &IPAddr{IP: negSvrTCPAddr.IP, Port: port, Zone: negSvrTCPAddr.Zone}, nil
}

type udpConn struct {
	negCon net.Conn
	net.Conn
}

func makeUDPPacket(addr net.Addr, data []byte) []byte {
	addrByts := AddrToBytes(addr)
	if len(addrByts) == 0 {
		return nil
	}
	return append([]byte{0, 0, 0}, append(AddrToBytes(addr), data...)...)
}

func (con *udpConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	pkt := makeUDPPacket(addr, data)
	if len(pkt) == 0 {
		return 0, ErrorAddressNotSupported
	}
	return con.Write(pkt)
}

func parseUDPPacket(p []byte) (net.Addr, []byte, error) {
	p = p[3:]
	switch p[0] {
	case AtypIPv4:
		return &net.UDPAddr{
			IP:   net.IPv4(p[1], p[2], p[3], p[4]),
			Port: (int(p[5]) << 8) | int(p[6]),
		}, p[7:], nil

	case AtypIPv6:
		return &net.UDPAddr{
			IP:   p[1:17],
			Port: (int(p[17]) << 8) | int(p[18]),
		}, p[19:], nil

	case AtypDomain:
		domainLen := int(p[1])
		return DomainAddr(string(p[2:domainLen]) + ":" + strconv.Itoa((int(p[2+domainLen])<<8)|int(p[3+domainLen]))), p[4+domainLen:], nil
	}
	return nil, nil, ErrorUnknowAddress
}

func (con *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := con.Read(b)
	if err != nil {
		return 0, nil, err
	}
	addr, data, err := parseUDPPacket(b[:n])
	if err != nil {
		return 0, nil, err
	}
	return copy(b, data), addr, nil
}

func (con *udpConn) Close() error {
	err := con.negCon.Close()
	if err != nil {
		con.Conn.Close()
		return err
	}
	return con.Conn.Close()
}
