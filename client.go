package gocks5

import (
	"errors"
	"net"
	"time"
)

func dial(addr string) (*Conn, error) {
	tcpCon, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Conn{tcpCon}, nil
}

func Dial(addr, user, pass string) (*Conn, time.Duration, error) {
	con, err := dial(addr)
	if err != nil {
		return nil, -1, err
	}
	frt, err := con.sendHandshake(user, pass)
	if err != nil {
		con.Close()
		return nil, frt, err
	}
	return con, frt, nil
}

var ErrorNotSuportedGSSAPI = errors.New("not suported GSSAPI")
var ErrorNoMethodAvailabled = errors.New("no method availabled")
var ErrorUnknowMethod = errors.New("unknow method")
var ErrorBadCertificate = errors.New("bad certificate")
var ErrorInvalidCertificate = errors.New("invalid certificate")
var ErrorAuthenticationFailed = errors.New("authentication failed")

func (con *Conn) sendHandshake(user, pass string) (time.Duration, error) {
	userLen := len(user)
	passLen := len(pass)
	hasUserPass := userLen > 0 || passLen > 0

	/*
		+----+----------+----------+
		|VER | NMETHODS | METHODS  |
		+----+----------+----------+
		| 1  |    1     | 1 to 255 |
		+----+----------+----------+
	*/

	p := []byte{Ver, 1, MethodNone}
	if hasUserPass {
		if userLen == 0 || userLen > 255 || passLen == 0 || passLen > 255 {
			return -1, ErrorBadCertificate
		}
		p[1]++
		p = append(p, MethodUsernamePassword)
	}

	now := time.Now()

	err := writeAll(con, p)
	if err != nil {
		return -1, err
	}
	authSz := 3 + userLen + passLen
	buf := make([]byte, authSz)

	/*
		+----+--------+
		|VER | METHOD |
		+----+--------+
		| 1  |   1    |
		+----+--------+
	*/

	err = readFull(con, buf[:2])
	if err != nil {
		return -1, err
	}

	frt := time.Now().Sub(now)

	switch buf[1] {
	case MethodNone:
		return frt, nil

	case MethodGSSAPI:
		return frt, ErrorNotSuportedGSSAPI

	case MethodUsernamePassword:
		/*
			+----+------+----------+------+----------+
			|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
			+----+------+----------+------+----------+
			| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
			+----+------+----------+------+----------+
		*/

		base := 0
		buf[base] = UserPassVer

		base++
		buf[base] = byte(userLen)

		base++
		copy(buf[base:], []byte(user))

		base += userLen
		buf[base] = byte(passLen)

		base++
		copy(buf[base:], []byte(pass))

		err := writeAll(con, buf)
		if err != nil {
			return frt, err
		}

		/*
			+----+--------+
			|VER | STATUS |
			+----+--------+
			| 1  |   1    |
			+----+--------+
		*/

		err = readFull(con, buf[:2])
		if err != nil {
			return frt, err
		}

		if buf[1] != UserPassStatusSuccess {
			return frt, ErrorAuthenticationFailed
		}
		return frt, nil

	case MethodUnsupportAll:
		return frt, ErrorNoMethodAvailabled
	}
	return frt, ErrorUnknowMethod
}

var ErrorServerFailure = errors.New("server failure")
var ErrorNotAllowed = errors.New("request not allowed")
var ErrorNetworkUnreachable = errors.New("network unreachable")
var ErrorHostUnreachable = errors.New("host unreachable")
var ErrorConnectionRefused = errors.New("connection refused")
var ErrorTTLExpired = errors.New("TTL expired")
var ErrorCommandNotSupported = errors.New("request command not supported")
var ErrorAddressNotSupported = errors.New("address not supported")
var ErrorUnknowReply = errors.New("unknow reply")

func (con *Conn) Command(cmd byte, addr net.Addr) (net.Addr, error) {
	err := con.WriteAddr(cmd, addr)
	if err != nil {
		return nil, err
	}
	rep, addr, err := con.ReadAddr()
	if err != nil {
		return nil, err
	}
	if rep != RepSuccess {
		switch rep {
		case RepServerFailure:
			return nil, ErrorServerFailure
		case RepNotAllowed:
			return nil, ErrorNotAllowed
		case RepNetworkUnreachable:
			return nil, ErrorNetworkUnreachable
		case RepHostUnreachable:
			return nil, ErrorHostUnreachable
		case RepConnectionRefused:
			return nil, ErrorConnectionRefused
		case RepTTLExpired:
			return nil, ErrorTTLExpired
		case RepCommandNotSupported:
			return nil, ErrorCommandNotSupported
		case RepAddressNotSupported:
			return nil, ErrorAddressNotSupported
		}
		return nil, ErrorUnknowReply
	}
	return addr, nil
}

func (con *Conn) DialTCP(addr net.Addr) (net.Conn, error) {
	_, err := con.Command(CmdConnect, addr)
	if err != nil {
		return nil, err
	}
	return con.Conn, nil
}

func DialTCP(server, user, pass string, dest net.Addr) (net.Conn, time.Duration, error) {
	con, frt, err := Dial(server, user, pass)
	if err != nil {
		return nil, frt, err
	}
	tcpCon, err := con.DialTCP(dest)
	if err != nil {
		con.Close()
		return nil, frt, err
	}
	return tcpCon, frt, err
}

func (con *Conn) ListenUDP() (net.PacketConn, error) {
	udpPxyAddr, err := con.Command(CmdUDP, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	udpPxyPubAddr, err := con.ResolveRemoteAddr(udpPxyAddr)
	if err != nil {
		return nil, err
	}
	udpPxyPubUDPAddr, err := AddrToUDP(udpPxyPubAddr)
	if err != nil {
		return nil, err
	}
	udpPxyUDPCon, err := net.DialUDP("udp", nil, udpPxyPubUDPAddr)
	if err != nil {
		return nil, err
	}
	return &udpConn{con.Conn, udpPxyUDPCon}, nil
}

func ListenUDP(server, user, pass string) (net.PacketConn, time.Duration, error) {
	con, frt, err := Dial(server, user, pass)
	if err != nil {
		return nil, frt, err
	}
	udpCon, err := con.ListenUDP()
	if err != nil {
		con.Close()
		return nil, frt, err
	}
	return udpCon, frt, err
}
