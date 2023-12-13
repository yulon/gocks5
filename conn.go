package gocks5

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/yulon/go-netil"
)

type Conn struct {
	net.Conn
	br *bufio.Reader
}

func newConn(rawCon net.Conn) *Conn {
	return &Conn{rawCon, bufio.NewReader(rawCon)}
}

func (con *Conn) Read(p []byte) (n int, err error) {
	return con.br.Read(p)
}

func (con *Conn) WriteAddr(typ byte, addr net.Addr) error {
	/*
		+----+-----+-------+------+----------+------+
		|VER | TYP |  RSV  | ATYP |   ADDR   | PORT |
		+----+-----+-------+------+----------+------+
		| 1  |  1  | X'00' |  1   | Variable |  2   |
		+----+-----+-------+------+----------+------+
	*/
	return netil.WriteAll(con, append([]byte{Ver, typ, 0}, AddrToBytes(addr)...))
}

var ErrorUnknowAddress = errors.New("unknow address")

func (con *Conn) ReadAddr() (byte, net.Addr, error) {
	var vtra [4]byte
	err := netil.ReadFull(con, vtra[:])
	if err != nil {
		return 0, nil, err
	}
	switch vtra[3] {
	case AtypIPv4:
		var addrBytes [6]byte
		err := netil.ReadFull(con, addrBytes[:])
		if err != nil {
			return vtra[1], nil, err
		}
		return vtra[1], &netil.IPPortAddr{
			IP:   net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]),
			Port: (int(addrBytes[4]) << 8) | int(addrBytes[5]),
		}, nil

	case AtypIPv6:
		var addrBytes [18]byte
		err := netil.ReadFull(con, addrBytes[:])
		if err != nil {
			return vtra[1], nil, err
		}
		return vtra[1], &netil.IPPortAddr{
			IP:   addrBytes[:16],
			Port: (int(addrBytes[16]) << 8) | int(addrBytes[17]),
		}, nil

	case AtypDomain:
		var domainLenBuf [1]byte
		err := netil.ReadFull(con, domainLenBuf[:])
		if err != nil {
			return vtra[1], nil, err
		}
		domainLen := int(domainLenBuf[0])
		addrBytes := make([]byte, domainLen+2)
		err = netil.ReadFull(con, addrBytes)
		if err != nil {
			return vtra[1], nil, err
		}
		return vtra[1], netil.DomainAddr(string(addrBytes[:domainLen]) + ":" + strconv.Itoa((int(addrBytes[domainLen])<<8)|int(addrBytes[domainLen+1]))), nil
	}
	return vtra[1], nil, ErrorUnknowAddress
}

func makeUDPPacket(addr net.Addr, data []byte) []byte {
	addrByts := AddrToBytes(addr)
	if len(addrByts) == 0 {
		return nil
	}
	return append([]byte{0, 0, 0}, append(addrByts, data...)...)
}

func makeUDPHeaderToBack(b []byte, addr net.Addr) int {
	n := AddrToBytesBack(b, addr)
	if n == 0 {
		return 0
	}
	lst := len(b) - 1 - n
	b[lst-2] = 0
	b[lst-1] = 0
	b[lst] = 0
	return 3 + n
}

var ErrorUnsupportedUDPFragment = errors.New("unsupported UDP fragments")

func parseUDPPacket(p []byte) (net.Addr, []byte, error) {
	if p[0] != 0 || p[1] != 0 {
		return nil, nil, fmt.Errorf("unsupported UDP package header, %+v", int(p[0])<<8|int(p[1]))
	}
	if p[2] != 0 {
		return nil, nil, ErrorUnsupportedUDPFragment
	}
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
		return netil.DomainAddr(string(p[2:domainLen]) + ":" + strconv.Itoa((int(p[2+domainLen])<<8)|int(p[3+domainLen]))), p[4+domainLen:], nil
	}
	return nil, nil, ErrorUnknowAddress
}

type packetConn struct {
	net.PacketConn
	pxyAddr      net.Addr
	keepAliveCon net.Conn
}

func newPacketConn(rawCon net.PacketConn, pxyAddr net.Addr, keepAliveCon net.Conn) *packetConn {
	return &packetConn{rawCon, pxyAddr, keepAliveCon}
}

func (pcon *packetConn) ReadFrom(b []byte) (n int, raddr net.Addr, err error) {
	n, _, raddr, err = pcon.ReadFromForward(b)
	return
}

func (pcon *packetConn) WriteTo(data []byte, raddr net.Addr) (int, error) {
	return pcon.WriteToForward(data, pcon.pxyAddr, raddr)
}

func (pcon *packetConn) Close() error {
	err := pcon.PacketConn.Close()
	if pcon.keepAliveCon == nil {
		return err
	}
	if err != nil {
		pcon.keepAliveCon.Close()
		return err
	}
	return pcon.keepAliveCon.Close()
}

func (pcon *packetConn) RemoteAddr() net.Addr {
	return pcon.pxyAddr
}

func (pcon *packetConn) ReadFromForward(b []byte) (n int, raddr, faddr net.Addr, err error) {
	var data []byte
	for {
		n, faddr, err = pcon.PacketConn.ReadFrom(b)
		if err != nil {
			return
		}
		raddr, data, err = parseUDPPacket(b[:n])
		if err == nil {
			break
		}
	}
	n = copy(b, data)
	return
}

func (pcon *packetConn) WriteToForward(data []byte, raddr, faddr net.Addr) (int, error) {
	pkt := makeUDPPacket(raddr, data)
	if len(pkt) == 0 {
		return 0, ErrorAddressNotSupported
	}
	return pcon.PacketConn.WriteTo(pkt, faddr)
}
